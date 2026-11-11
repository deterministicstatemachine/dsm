// SPDX-License-Identifier: MIT OR Apache-2.0

//! A relationship opens and ends on its own chain (DSM Amendment A33). Two
//! devices on the network's pinned set of storage nodes; every step here is
//! the real one: the maker's ESTABLISH or TERMINATE delivered to the spool,
//! the other device's countersignature on its own sync, the maker's
//! finalization on the countersignature.

use serial_test::serial;

use crate::storage::client_db::{self, RelationshipState};
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::core::relationship_lifecycle::RelationshipLifecycle;
use dsm::types::proto as generated;

/// The relationship's lifecycle on `device`'s own chain for `peer`.
fn chain_lifecycle(device: &TestDevice, peer: &TestDevice) -> RelationshipLifecycle {
    device.enter();
    device
        .router()
        .core_sdk
        .relationship_lifecycle(peer.device_id)
        .expect("the device holds the relationship's leaf")
}

/// The send-status Rust derives for `peer` on `device`, as the wallet reads it.
fn send_status(device: &TestDevice, peer: &TestDevice) -> generated::RelationshipSendStatus {
    device.enter();
    crate::handlers::relationship_status::derive_local_send_status_for_device_id(&peer.device_id)
}

/// A device that added a contact its contact has not added back sends
/// nothing: the wallet refuses before anything is built, with the reason.
/// If it is the maker, its establishment step is in flight and unsigned by
/// the other side; if not, nothing is on the chain at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_send_before_the_other_side_adds_is_refused_and_nothing_leaves() {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    // A adds C; C has not added A. Whichever of them would make the step,
    // nothing is established: one side alone cannot.
    p.a.add_and_establish(&c).await;
    let a_makes =
        crate::handlers::relationship_lifecycle::makes_establishment(&p.a.device_id, &c.device_id);
    if a_makes {
        assert_eq!(p.a.relationship_state(&c), RelationshipState::Proposed);
        assert_eq!(
            chain_lifecycle(&p.a, &c),
            RelationshipLifecycle::Established
        );
    } else {
        assert_eq!(p.a.relationship_state(&c), RelationshipState::Opened);
        assert_eq!(chain_lifecycle(&p.a, &c), RelationshipLifecycle::Opened);
    }
    let status = send_status(&p.a, &c);
    assert!(!status.send_ready, "{status:?}");
    assert_eq!(
        status.send_block_reason,
        generated::RelationshipSendBlockReason::NotEstablished as i32,
        "{status:?}"
    );
    let before = p.a.era_balance();
    let refused = p.a.send(&c, 10).await;
    assert!(!refused.success, "the send went: {:?}", refused.data);
    let why = refused
        .error_message
        .expect("a refused send carries its reason");
    assert!(why.contains("not send-ready"), "{why}");
    assert_eq!(p.a.era_balance(), before, "nothing was debited");
    // No transfer was proposed: the only step in flight on the relationship,
    // if any, is the maker's establishment.
    p.a.enter();
    let proposal = client_db::get_unfinalized_proposal_for_relationship(&p.a.rel_key_with(&c))
        .expect("the proposals");
    match proposal {
        Some(step) => assert!(
            step.is_lifecycle_step(),
            "a transfer was proposed: {step:?}"
        ),
        None => assert!(!a_makes, "the maker's establishment is not in flight"),
    }
}

/// Both sides adding each other establishes the relationship: the maker's
/// step, countersigned by the other device, is on both chains, and the
/// first transfer then goes through and is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn adding_each_other_establishes_the_relationship_on_both_sides() {
    let p = Pair::boot(100, 0).await;
    assert_eq!(
        chain_lifecycle(&p.a, &p.b),
        RelationshipLifecycle::Established
    );
    assert_eq!(
        chain_lifecycle(&p.b, &p.a),
        RelationshipLifecycle::Established
    );
    assert_eq!(p.a.relationship_state(&p.b), RelationshipState::Established);
    assert_eq!(p.b.relationship_state(&p.a), RelationshipState::Established);
    assert!(send_status(&p.a, &p.b).send_ready);
    assert!(send_status(&p.b, &p.a).send_ready);

    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);
    for _ in 0..6 {
        p.b.sync().await;
        p.a.sync().await;
        if p.b.era_balance() == 10 {
            break;
        }
    }
    assert_eq!(p.b.era_balance(), 10, "B took A's first transfer");
}

/// A relationship ended by one side refuses sends on both sides and takes
/// no transfer: the terminator's wallet refuses at once, the other side's
/// once it has read and acknowledged the step, and the chains hold Ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_ended_relationship_refuses_sends_both_ways_and_takes_no_transfer() {
    let p = Pair::boot(100, 100).await;
    p.b.enter();
    let ended =
        p.b.invoke(
            "contacts.terminate",
            &generated::ContactTerminateRequest {
                device_id: p.a.device_id.to_vec(),
            },
        )
        .await;
    assert!(ended.success, "{:?}", ended.error_message);
    assert_eq!(chain_lifecycle(&p.b, &p.a), RelationshipLifecycle::Ended);
    // Ending, then ended once A acknowledges.
    assert!(p.b.relationship_state(&p.a).is_over());
    let status = send_status(&p.b, &p.a);
    assert!(!status.send_ready, "{status:?}");

    for _ in 0..6 {
        p.a.sync().await;
        p.b.sync().await;
        if p.a.relationship_state(&p.b) == RelationshipState::Ended
            && p.b.relationship_state(&p.a) == RelationshipState::Ended
        {
            break;
        }
    }
    assert_eq!(p.a.relationship_state(&p.b), RelationshipState::Ended);
    assert_eq!(p.b.relationship_state(&p.a), RelationshipState::Ended);
    assert_eq!(chain_lifecycle(&p.a, &p.b), RelationshipLifecycle::Ended);
    let status = send_status(&p.a, &p.b);
    assert_eq!(
        status.send_block_reason,
        generated::RelationshipSendBlockReason::Ended as i32,
        "{status:?}"
    );
    let before_a = p.a.era_balance();
    let refused = p.a.send(&p.b, 5).await;
    assert!(!refused.success, "A sent on an ended relationship");
    assert_eq!(p.a.era_balance(), before_a);
    let refused = p.b.send(&p.a, 5).await;
    assert!(!refused.success, "B sent on an ended relationship");
    // Ending again is refused: a termination is final.
    let again =
        p.b.invoke(
            "contacts.terminate",
            &generated::ContactTerminateRequest {
                device_id: p.a.device_id.to_vec(),
            },
        )
        .await;
    assert!(!again.success);
    let why = again
        .error_message
        .expect("a refused termination carries its reason");
    assert!(
        why.contains("already ended"),
        "a second termination was not refused as final: {why}"
    );
}

/// A device whose contact never added it back ends the relationship alone:
/// its wallet refuses everything on it from then on. The device that would
/// not make the establishment ends it with a TERMINATE step from `h_0`; the
/// maker, whose establishment is still in flight, ends it on its own record
/// (one step at a time).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_maker_ends_a_relationship_its_contact_never_added_back() {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    p.a.add_and_establish(&c).await;
    let a_makes =
        crate::handlers::relationship_lifecycle::makes_establishment(&p.a.device_id, &c.device_id);
    p.a.enter();
    let ended =
        p.a.invoke(
            "contacts.terminate",
            &generated::ContactTerminateRequest {
                device_id: c.device_id.to_vec(),
            },
        )
        .await;
    assert!(ended.success, "{:?}", ended.error_message);
    if a_makes {
        assert_eq!(p.a.relationship_state(&c), RelationshipState::Ended);
    } else {
        assert_eq!(chain_lifecycle(&p.a, &c), RelationshipLifecycle::Ended);
    }
    assert!(p.a.relationship_state(&c).is_over());
    let status = send_status(&p.a, &c);
    assert!(!status.send_ready, "{status:?}");
    assert!(
        matches!(
            generated::RelationshipSendBlockReason::try_from(status.send_block_reason),
            Ok(generated::RelationshipSendBlockReason::Ending)
                | Ok(generated::RelationshipSendBlockReason::Ended)
        ),
        "{status:?}"
    );
}
