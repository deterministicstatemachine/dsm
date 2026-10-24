// SPDX-License-Identifier: Apache-2.0

//! Offline boundaries through their routes, on the network's pinned set of
//! storage nodes: a load and an unload are admitted economic transitions, each
//! at the next economic position, each walkable by a foreign verifier as the
//! boundary it is, and an unload's online credit is funded by exactly its
//! offline debit.

use serial_test::serial;

use crate::economic_fixtures::{self, foreign_walk};
use crate::test_support::appliance::HostAppliance;
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::types::device_state::OfflineBoundaryKind;

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

/// ERA base units per whole ERA.
fn scale() -> u64 {
    10u64.pow(
        dsm::core::token::era_policy::era_policy()
            .expect("ERA's policy")
            .decimals,
    )
}

fn admitted_position() -> u64 {
    economic_fixtures::admitted_position().expect("the device is activated")
}

/// `method` for `amount` ERA, entered as the wallet shows it. An admission the
/// fleet has not yet made final is held, and finished by resuming it exactly
/// as the device resumes it before anything else; a refusal with nothing held
/// is returned.
async fn boundary(device: &TestDevice, method: &str, amount: &str) -> Result<(), String> {
    let result = device
        .invoke(
            method,
            &crate::generated::OfflineCashRequest {
                token_id: "ERA".to_string(),
                amount: amount.to_string(),
            },
        )
        .await;
    if result.success {
        return Ok(());
    }
    let core = device.router().core_sdk.clone();
    let mut error = format!("{:?}", result.error_message);
    for resumed in 1..=4u64 {
        let Some(pending) = core
            .device_head()
            .and_then(|head| head.pending_economic_admission().cloned())
        else {
            return Err(error);
        };
        tokio::time::sleep(std::time::Duration::from_millis(250 * resumed)).await;
        match crate::sdk::economic_admission_flow::resume_pending_admission(
            &core,
            economic_fixtures::NETWORK,
            pending,
        )
        .await
        {
            Ok(_) => return Ok(()),
            Err(e) => error = e.to_string(),
        }
    }
    Err(error)
}

/// A load and an unload each land at the next economic position; the online
/// balance and the offline account move by the same amount; a foreign
/// verifier walks each position as that boundary; and the unload's online
/// credit is funded by its offline debit. More than the account holds is not
/// unloaded, more than the balance holds is not loaded, and neither refusal
/// admits anything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_load_and_an_unload_are_admitted_and_walkable_and_an_unload_funds_once() {
    let pair = Pair::boot(100, 0).await;
    let _appliance = HostAppliance::birth(&pair.a, [0xC4; 32], 16).install();
    pair.a.enter();
    let core = pair.a.router().core_sdk.clone();
    let start = admitted_position();
    let online = pair.a.era_balance();

    boundary(&pair.a, "wallet.loadOffline", "20.00")
        .await
        .expect("the load is admitted");
    assert_eq!(
        admitted_position(),
        start + 1,
        "the load is its own position"
    );
    assert_eq!(pair.a.era_balance(), online - 20 * scale());
    assert_eq!(core.offline_allocation_of(&era()), Some(20 * scale()));
    let head = core.device_head().expect("a head");
    assert!(head.pending_economic_admission().is_none());
    let walked = foreign_walk(head.genesis_digest(), head.devid(), start + 1).await;
    let load = walked
        .offline_boundary()
        .expect("the position is a boundary");
    assert_eq!(load.kind(), OfflineBoundaryKind::Load);
    assert_eq!(load.amount(), 20 * scale());
    assert!(
        walked.witness().credit_sources.is_empty(),
        "a load funds nothing"
    );

    boundary(&pair.a, "wallet.unloadOffline", "5.00")
        .await
        .expect("the unload is admitted");
    assert_eq!(admitted_position(), start + 2);
    assert_eq!(pair.a.era_balance(), online - 15 * scale());
    assert_eq!(core.offline_allocation_of(&era()), Some(15 * scale()));
    let head = core.device_head().expect("a head");
    let walked = foreign_walk(head.genesis_digest(), head.devid(), start + 2).await;
    let unload = walked
        .offline_boundary()
        .expect("the position is a boundary");
    assert_eq!(unload.kind(), OfflineBoundaryKind::Unload);
    assert!(
        matches!(
            walked.witness().credit_sources.as_slice(),
            [dsm::economic::credit::CreditSource::OfflineBoundaryDebit(_)]
        ),
        "the unload's credit is funded by its offline debit"
    );

    let refused = boundary(&pair.a, "wallet.unloadOffline", "16.00")
        .await
        .expect_err("more than the account holds");
    assert!(
        refused.contains("more than the offline allocation holds"),
        "{refused}"
    );
    let refused = boundary(&pair.a, "wallet.loadOffline", "100.00")
        .await
        .expect_err("more than the online balance holds");
    assert!(
        refused.contains("more than the online balance"),
        "{refused}"
    );
    assert_eq!(admitted_position(), start + 2, "no refusal admits anything");
    assert_eq!(core.offline_allocation_of(&era()), Some(15 * scale()));
}

/// A's offline account under `bundle` as A's own device holds it: its root
/// and its funding chain.
fn own_account(device: &TestDevice, bundle: &[u8; 32]) -> ([u8; 32], Option<[u8; 32]>) {
    device.enter();
    let head = device.router().core_sdk.device_head().expect("a head");
    let account = head
        .offline_account(bundle)
        .expect("the device holds the account");
    (account.root(), account.funding_chain())
}

/// B's record of A's offline account under `bundle`, as B last validated it.
fn recorded_by(
    device: &TestDevice,
    peer: ([u8; 32], [u8; 32]),
    bundle: &[u8; 32],
) -> Option<dsm::economic::peer_lineage::PeerOfflineAccount> {
    device.enter();
    crate::storage::client_db::economic_lineage::latest_offline_account(&peer.0, &peer.1, bundle)
        .expect("B's store reads")
}

/// The owner's receive rule (2026-10-22): a contact's offline account is
/// trusted offline only as the receiver validated it from the contact's
/// online history. B's own walk of A's history through A's load records the
/// account the load left, under A's anchor bundle — exactly the root and
/// funding chain A's device holds — and after A's unload, B's next walk
/// records the account the unload left as the latest. Before B walks, B
/// knows nothing of the account.
/// MUTATION CONTROL: not keeping the account a passed boundary step left
/// leaves B with nothing recorded and turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_contacts_walk_records_the_offline_account_each_boundary_left() {
    use crate::anchor::AnchorAppliance;

    let pair = Pair::boot(100, 0).await;
    let appliance = HostAppliance::birth(&pair.a, [0xC4; 32], 16).install();
    let bundle = appliance.pin().bundle;
    pair.a.enter();
    let start = admitted_position();
    let a = {
        let head = pair.a.router().core_sdk.device_head().expect("a head");
        (head.genesis_digest(), head.devid())
    };

    boundary(&pair.a, "wallet.loadOffline", "20.00")
        .await
        .expect("the load is admitted");
    let (loaded_root, loaded_chain) = own_account(&pair.a, &bundle);
    assert!(
        recorded_by(&pair.b, a, &bundle).is_none(),
        "B has validated nothing of A's offline account"
    );
    pair.b.enter();
    foreign_walk(a.0, a.1, start + 1).await;
    let recorded = recorded_by(&pair.b, a, &bundle).expect("B recorded the load");
    assert_eq!(recorded.economic_position(), start + 1);
    assert_eq!(
        recorded.account_root(),
        &loaded_root,
        "the account the load left"
    );
    assert_eq!(
        Some(*recorded.funding_chain()),
        loaded_chain,
        "the funding chain the load left"
    );

    boundary(&pair.a, "wallet.unloadOffline", "5.00")
        .await
        .expect("the unload is admitted");
    let (unloaded_root, unloaded_chain) = own_account(&pair.a, &bundle);
    assert_ne!(unloaded_root, loaded_root, "the unload moved the account");
    pair.b.enter();
    foreign_walk(a.0, a.1, start + 2).await;
    let recorded = recorded_by(&pair.b, a, &bundle).expect("B recorded the unload");
    assert_eq!(recorded.economic_position(), start + 2);
    assert_eq!(
        recorded.account_root(),
        &unloaded_root,
        "the account the unload left"
    );
    assert_eq!(Some(*recorded.funding_chain()), unloaded_chain);
}
