// SPDX-License-Identifier: MIT OR Apache-2.0
//! Economic admissions held for resume while the members refuse object
//! writes (owner rulings, 2026-10-30, from the many-device fault test):
//! - a recipient whose admission is held is not marked diverged, and is
//!   send-ready toward the sender once the admission is finished;
//! - a send whose admission is held is finished by the sender's own sync once
//!   its handler has returned, with no second send, and is delivered;
//! - while the handler that created an admission runs, the sync leaves the
//!   admission to it, and applies no inbound transfer behind it;
//! - a sync racing a send admits and delivers each send once.

use super::{Pair, TestDevice};
use crate::economic_fixtures;

/// Whether the device holds an economic admission pending.
fn admission_pending(device: &TestDevice) -> bool {
    device.enter();
    device
        .router()
        .core_sdk
        .device_head()
        .and_then(|head| head.pending_economic_admission().cloned())
        .is_some()
}

/// Rounds of syncs, `first` then `second`, until neither holds an admission
/// pending and both are send-ready toward each other.
async fn come_to_rest(first: &TestDevice, second: &TestDevice) {
    for round in 0..6 {
        let one = first.sync().await;
        let two = second.sync().await;
        let ready = [(first, second), (second, first)].iter().all(|(me, peer)| {
            me.enter();
            super::send_status(peer).send_ready
        });
        if ready && !admission_pending(first) && !admission_pending(second) {
            return;
        }
        assert!(
            round < 5,
            "no rest: {} {:?}; {} {:?}",
            first.slot,
            one.errors,
            second.slot,
            two.errors
        );
    }
}

/// A recipient whose economic admission is held while the members refuse
/// object writes is not marked diverged: once they take writes again its next
/// syncs finish the admission, and it is send-ready toward the sender.
/// MUTATION CONTROL: marking the sender's contact for online reconciliation
/// when the admission is held turns this red ("diverged and needs repair").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_recipients_held_admission_marks_nothing_diverged() {
    let p = Pair::boot(100, 100).await;
    let b_before = p.b.era_balance();
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    let breaking = economic_fixtures::members_to_break_quorum();
    p.nodes.refuse_object_writes(&breaking).await;
    p.b.sync().await;
    assert!(
        admission_pending(&p.b),
        "B's admission of A's transfer is held while the members refuse writes"
    );
    p.nodes.accept_object_writes(&breaking).await;
    come_to_rest(&p.b, &p.a).await;
    assert_eq!(p.b.era_balance(), b_before + 10, "B is credited once");
    super::generation(&p.b, &p.a, 3).await;
}

/// A send whose economic admission is held while the members refuse object
/// writes is finished by the sender's own sync once they take writes again,
/// with no second send: the send is answered as committed, the transfer is
/// delivered, the recipient is credited, and both are send-ready.
/// MUTATION CONTROL: the sync finishing only an admission that predates the
/// process turns this red (the send is never delivered).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_senders_held_admission_is_finished_by_its_own_sync() {
    let p = Pair::boot(100, 100).await;
    let b_before = p.b.era_balance();
    let breaking = economic_fixtures::members_to_break_quorum();
    p.nodes.refuse_object_writes(&breaking).await;
    let sent = p.a.send(&p.b, 10).await;
    let said = crate::test_support::two_device::committed_send_message(&sent);
    assert!(
        admission_pending(&p.a),
        "A's admission is held while the members refuse writes: {said}"
    );
    p.nodes.accept_object_writes(&breaking).await;
    come_to_rest(&p.a, &p.b).await;
    assert_eq!(p.b.era_balance(), b_before + 10, "B is credited once");
    super::generation(&p.a, &p.b, 3).await;
}

/// While the handler that created an admission runs, the sync leaves the
/// device's pending admission to it; once the handler returns, the sync
/// finishes it.
/// MUTATION CONTROL: the sync finishing a held admission while a handler runs
/// turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn the_sync_leaves_a_held_admission_to_its_running_handler() {
    let p = Pair::boot(100, 100).await;
    let breaking = economic_fixtures::members_to_break_quorum();
    p.nodes.refuse_object_writes(&breaking).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(
        admission_pending(&p.a),
        "A's admission is held while the members refuse writes: {:?}",
        sent.error_message
    );
    p.nodes.accept_object_writes(&breaking).await;
    p.a.enter();
    let running = p.a.router().core_sdk.admission_handler();
    p.a.sync().await;
    assert!(
        admission_pending(&p.a),
        "the sync leaves the admission to the handler that runs"
    );
    drop(running);
    p.a.sync().await;
    assert!(
        !admission_pending(&p.a),
        "the handler returned: the sync finishes the admission"
    );
}

/// While a handler that creates an economic admission runs, the sync applies
/// no inbound transfer: every apply would admit behind that handler's
/// admission, so the pass holds its pairs, and the next pass after the handler
/// returns applies them.
/// MUTATION CONTROL: the pass applying its pairs while another admission
/// handler runs turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_sync_holds_its_pairs_while_another_admission_handler_runs() {
    let p = Pair::boot(100, 100).await;
    let b_before = p.b.era_balance();
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    p.b.enter();
    let running = p.b.router().core_sdk.admission_handler();
    p.b.sync().await;
    assert_eq!(
        p.b.era_balance(),
        b_before,
        "B applies nothing while its own admission handler runs"
    );
    drop(running);
    come_to_rest(&p.b, &p.a).await;
    assert_eq!(p.b.era_balance(), b_before + 10, "B is credited once");
}

/// A sync racing a send on the same device, round after round, every other
/// round with the members refusing object writes so that the send's
/// admission is held while the sync runs: whichever reaches the admission
/// first, each send answers as committed exactly when it debited, and at rest
/// every committed send is credited exactly once, applied once by the
/// recipient, and nothing is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial_test::serial]
async fn a_sync_racing_a_send_admits_and_delivers_each_send_once() {
    use crate::bridge::{AppInvoke, AppRouter};
    use dsm::types::proto as generated;
    use prost::Message;
    let p = Pair::boot(100, 100).await;
    let rel = p.a.rel_key_with(&p.b);
    let breaking = economic_fixtures::members_to_break_quorum();
    let (a0, b0) = (p.a.era_balance(), p.b.era_balance());
    let decimals = crate::handlers::wallet_routes::token_decimals("ERA").expect("ERA's decimals");
    let packed = |body: Vec<u8>| {
        generated::ArgPack {
            codec: generated::Codec::Proto as i32,
            body,
            schema_hash: None,
        }
        .encode_to_vec()
    };
    let mut committed = 0;
    let mut paid = 0;
    for round in 0..6u64 {
        let refusing = round % 2 == 1;
        if refusing {
            p.nodes.refuse_object_writes(&breaking).await;
        }
        let amount = round + 1;
        p.a.enter();
        let router = p.a.router();
        let send = router.invoke(AppInvoke {
            method: "wallet.sendSmart".to_string(),
            args: packed(
                generated::OnlineTransferSmartRequest {
                    recipient_device_id: p.b.device_id.to_vec(),
                    amount: crate::handlers::wallet_routes::format_base_units_for_display(
                        amount, decimals,
                    ),
                    token_id: "ERA".to_string(),
                    memo: format!("race #{round}"),
                }
                .encode_to_vec(),
            ),
        });
        let sync = router.invoke(AppInvoke {
            method: "storage.sync".to_string(),
            args: packed(crate::sdk::inbox_poller::poll_sync_request().encode_to_vec()),
        });
        let (sent, synced) = tokio::join!(send, sync);
        assert!(synced.success, "round {round}: {:?}", synced.error_message);
        p.a.enter();
        let armed = super::gate_present(&p.b);
        assert_eq!(
            sent.success, armed,
            "round {round}: the send answers as committed exactly when it debited: {:?}",
            sent.error_message
        );
        if armed {
            committed += 1;
            paid += amount;
        }
        if refusing {
            p.nodes.accept_object_writes(&breaking).await;
        }
        come_to_rest(&p.a, &p.b).await;
        assert_eq!(
            p.a.era_balance(),
            a0 - paid,
            "round {round}: A debited once"
        );
        assert_eq!(
            p.b.era_balance(),
            b0 + paid,
            "round {round}: B credited once"
        );
        p.b.enter();
        assert_eq!(
            super::rows_for_relationship("canonical_apply_identity", &rel),
            committed,
            "round {round}: B applied each committed send once"
        );
    }
    assert_eq!(committed, 6, "every racing send committed");
}
