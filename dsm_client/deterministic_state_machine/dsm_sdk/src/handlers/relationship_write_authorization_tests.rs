// SPDX-License-Identifier: MIT OR Apache-2.0

//! A relationship's write keys and grants (DSM Amendment A34), between two
//! devices on the network's pinned set of storage nodes. Every message here is
//! the real one: the maker's offer delivered with its ESTABLISH, the other
//! device's offer and grant made in the sync that applies the step, the
//! maker's grant in the sync that finalizes on the countersignature.

use serial_test::serial;

use super::relationship_write_authorization::WriteAuthorizationChecked;
use crate::storage::client_db::{self, IssuedWriteGrant, OwnWriteAuthorization};
use crate::test_support::two_device::{Pair, TestDevice};
use dsm::core::relationship_write_grant::{
    decode_write_authorization_wire, decode_write_grant_wire, verify_write_authorization,
    AuthorizationExpectation, WriteKeyOffer, WRITE_KEY_VARIANT,
};
use prost::Message;

/// `device`'s own write authorization toward `peer`, and the grant it issued
/// `peer`, as its database holds them.
fn rows(
    device: &TestDevice,
    peer: &TestDevice,
) -> (Option<OwnWriteAuthorization>, Option<IssuedWriteGrant>) {
    device.enter();
    (
        client_db::own_write_authorization(&peer.device_id).expect("the own row"),
        client_db::issued_write_grant(&peer.device_id).expect("the issued row"),
    )
}

/// Both rows, both present.
fn held(device: &TestDevice, peer: &TestDevice) -> (OwnWriteAuthorization, IssuedWriteGrant) {
    match rows(device, peer) {
        (Some(own), Some(issued)) => (own, issued),
        other => panic!("{} holds {other:?} toward {}", device.slot, peer.slot),
    }
}

/// Sync both devices, as their pollers would, until each holds the other's
/// grant for its own key. Panics with the last syncs' errors otherwise.
async fn granted_both_ways(a: &TestDevice, b: &TestDevice) {
    let mut last_errors = Vec::new();
    for _ in 0..6 {
        let both = [(a, b), (b, a)].iter().all(|(device, peer)| {
            matches!(rows(device, peer), (Some(own), Some(_)) if own.grant.is_some())
        });
        if both {
            return;
        }
        let mine = a.sync().await;
        let theirs = b.sync().await;
        last_errors = mine.errors.into_iter().chain(theirs.errors).collect();
    }
    panic!(
        "{} and {} did not grant each other: {:?} / {:?}; the last syncs said: {}",
        a.slot,
        b.slot,
        rows(a, b),
        rows(b, a),
        last_errors.join(" | ")
    );
}

/// `device`'s held grant for its key toward `peer` verifies under `peer`'s
/// AK and names exactly the instance, the two devices and the key.
fn assert_grant_verifies(device: &TestDevice, peer: &TestDevice, own: &OwnWriteAuthorization) {
    let grant = own.grant.as_ref().expect("a grant is held");
    let checked = verify_write_authorization(
        &grant.grant_wire,
        &AuthorizationExpectation {
            relationship_instance_id: &own.relationship_instance_id,
            recipient_genesis: &peer.genesis,
            recipient_device_id: &peer.device_id,
            sender_device_id: &device.device_id,
            write_public_key: &own.write_public_key,
            recipient_ak: &peer.ak_pk,
        },
    )
    .expect("the authorization verifies under the granter's AK");
    assert_eq!(checked.grant.grant_id(), grant.grant_id);
    assert_ne!(
        checked.lock.lock_public_key, peer.ak_pk,
        "the lock is never the granter's AK"
    );
}

/// Establishing a relationship gives each side a write key of its own toward
/// the other and the other's grant for it: two independent directional
/// authorizations for one instance, each the other side's issued grant, none
/// of them an AK, all delivered. Nobody waited for anything the
/// establishment does not already wait for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn establishing_gives_each_side_its_own_key_and_the_others_grant() {
    let p = Pair::boot(100, 0).await;
    granted_both_ways(&p.a, &p.b).await;
    let (a_own, a_issued) = held(&p.a, &p.b);
    let (b_own, b_issued) = held(&p.b, &p.a);

    assert_eq!(
        a_own.relationship_instance_id, b_own.relationship_instance_id,
        "both sides name the one instance their establishment opened"
    );
    assert_ne!(a_own.write_public_key, b_own.write_public_key);
    for key in [&a_own.write_public_key, &b_own.write_public_key] {
        assert_ne!(key, &p.a.ak_pk, "a write key is never an AK");
        assert_ne!(key, &p.b.ak_pk, "a write key is never an AK");
    }
    // What each side issued is the other's key, and what each side holds is
    // the other's issued grant.
    assert_eq!(a_issued.write_public_key, b_own.write_public_key);
    assert_eq!(b_issued.write_public_key, a_own.write_public_key);
    assert_eq!(
        a_own.grant.as_ref().map(|g| &g.grant_wire),
        Some(&b_issued.grant.grant_wire)
    );
    assert_eq!(
        b_own.grant.as_ref().map(|g| &g.grant_wire),
        Some(&a_issued.grant.grant_wire)
    );
    assert_grant_verifies(&p.a, &p.b, &a_own);
    assert_grant_verifies(&p.b, &p.a, &b_own);
    // Everything owed went out.
    assert!(a_own.offer_delivered && a_issued.delivered);
    assert!(b_own.offer_delivered && b_issued.delivered);
    for device in [&p.a, &p.b] {
        device.enter();
        assert!(client_db::owed_write_authorizations()
            .expect("owed")
            .is_empty());
    }
}

/// A device that closes its store and starts again holds the same
/// authorizations, and they still verify; the next syncs change nothing and
/// owe nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn the_authorizations_survive_a_restart() {
    let mut p = Pair::boot(100, 0).await;
    granted_both_ways(&p.a, &p.b).await;
    let before = rows(&p.a, &p.b);

    // A new process over the same file: the connection dropped, a new router.
    p.a.enter();
    client_db::close_database_for_tests();
    p.a.start(&p.fleet);
    let after = rows(&p.a, &p.b);
    assert_eq!(after, before);
    let (a_own, _) = held(&p.a, &p.b);
    assert_grant_verifies(&p.a, &p.b, &a_own);

    p.a.sync().await;
    p.b.sync().await;
    assert_eq!(rows(&p.a, &p.b), before);
    p.a.enter();
    assert!(client_db::owed_write_authorizations()
        .expect("owed")
        .is_empty());
}

/// An establishment that never finished leaves no grant anyone can use: a
/// device whose contact never added it back holds no grant from it, and the
/// contact, holding no relationship, grants nothing. A device that has added
/// but not established takes an offer as not yet answerable, and grants
/// nothing either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_establishment_that_never_finished_leaves_no_usable_grant() {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    p.a.add_and_establish(&c).await;
    for _ in 0..3 {
        p.a.sync().await;
        c.sync().await;
    }
    let (a_own, a_issued) = rows(&p.a, &c);
    assert!(
        a_own.as_ref().is_none_or(|own| own.grant.is_none()),
        "A holds a grant from a device that never added it: {a_own:?}"
    );
    assert_eq!(a_issued, None);
    assert_eq!(rows(&c, &p.a), (None, None), "C holds nothing toward A");

    // An offer from A for C, read by C before C adds A: from no contact.
    p.a.enter();
    let offer = super::relationship_write_authorization::build_own_offer(
        &p.a.router().wallet,
        &p.a.device_id,
        &c.device_id,
        &p.a.rel_key_with(&c),
        &[0x7E; 32],
    )
    .expect("A's offer");
    c.enter();
    assert!(matches!(
        c.router().take_in_write_key_offer(&offer.wire).await,
        WriteAuthorizationChecked::Refused(_)
    ));
    assert_eq!(rows(&c, &p.a), (None, None));

    // C adds A, and nothing is established yet: the offer waits.
    c.add_contact(&p.a).await;
    assert!(!c.relationship_state(&p.a).admits_value());
    c.enter();
    assert!(matches!(
        c.router().take_in_write_key_offer(&offer.wire).await,
        WriteAuthorizationChecked::NotEstablished(_)
    ));
    c.enter();
    assert_eq!(
        client_db::issued_write_grant(&p.a.device_id).expect("issued"),
        None,
        "C granted a key on a relationship it has not established"
    );
}

/// Reading the same offer or grant again changes nothing, and a second key
/// for the same instance, bound by the sender's own AK and proving
/// possession, is refused: one grant per sender, never two.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_repeated_offer_or_grant_changes_nothing_and_a_second_key_is_refused() {
    let p = Pair::boot(100, 0).await;
    granted_both_ways(&p.a, &p.b).await;
    let (a_own, _) = held(&p.a, &p.b);
    let b_before = rows(&p.b, &p.a);
    let a_before = rows(&p.a, &p.b);

    p.b.enter();
    assert_eq!(
        p.b.router()
            .take_in_write_key_offer(&a_own.offer_wire)
            .await,
        WriteAuthorizationChecked::Done
    );
    assert_eq!(rows(&p.b, &p.a), b_before);
    let grant = a_own.grant.as_ref().expect("A's grant");
    p.a.enter();
    assert_eq!(
        p.a.router().take_in_write_grant(&grant.grant_wire),
        WriteAuthorizationChecked::Done
    );
    assert_eq!(rows(&p.a, &p.b), a_before);

    // A second key A offers for the same instance.
    p.a.enter();
    let second = dsm::crypto::sphincs::generate_keypair(WRITE_KEY_VARIANT).expect("a key");
    let offer = WriteKeyOffer {
        relationship_instance_id: a_own.relationship_instance_id,
        sender_device_id: p.a.device_id,
        recipient_device_id: p.b.device_id,
        write_public_key: second.public_key.clone(),
    };
    let possession =
        dsm::crypto::sphincs::sphincs_sign(&second.secret_key, &offer.possession_target())
            .expect("possession");
    let binding =
        p.a.router()
            .wallet
            .sign_operation_bytes(&offer.binding_target())
            .expect("binding");
    let wire = offer.to_wire(possession, binding).encode_to_vec();
    p.b.enter();
    assert!(matches!(
        p.b.router().take_in_write_key_offer(&wire).await,
        WriteAuthorizationChecked::Refused(_)
    ));
    assert_eq!(rows(&p.b, &p.a), b_before);
}

/// An offer or a grant read by a device it does not name is refused there,
/// and leaves nothing: another recipient's grant authorizes nothing for this
/// device, and another sender's offer is not this device's to answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn an_offer_or_grant_for_another_device_is_refused() {
    let p = Pair::boot(100, 0).await;
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    granted_both_ways(&p.a, &p.b).await;
    let (a_own, _) = held(&p.a, &p.b);
    let grant = a_own.grant.as_ref().expect("A's grant");

    c.enter();
    assert!(matches!(
        c.router().take_in_write_key_offer(&a_own.offer_wire).await,
        WriteAuthorizationChecked::Refused(_)
    ));
    assert!(matches!(
        c.router().take_in_write_grant(&grant.grant_wire),
        WriteAuthorizationChecked::Refused(_)
    ));
    // B's grant, one byte changed in the lock's signature, read by A:
    // refused, and A keeps the grant it held.
    let mut authorization =
        decode_write_authorization_wire(&grant.grant_wire).expect("the authorization");
    let mut tampered = decode_write_grant_wire(&authorization.grant).expect("the grant");
    tampered.grant_signature[64] ^= 0x01;
    authorization.grant = tampered.encode_to_vec();
    p.a.enter();
    assert!(matches!(
        p.a.router()
            .take_in_write_grant(&authorization.encode_to_vec()),
        WriteAuthorizationChecked::Refused(_)
    ));
    assert_eq!(held(&p.a, &p.b).0, a_own);
    c.enter();
    assert!(client_db::owed_write_authorizations()
        .expect("owed")
        .is_empty());
}

/// DSM Amendment A34, the write lock: every node refuses a write into an
/// inbox under any key but the recipient's lock, by derivation alone. A pays
/// B; a stranger who somehow learned the route A's payment took writes to
/// that inbox under a key of its own, well signed: every member answers 403,
/// the ones A's delivery never reached included. B is still paid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_write_into_an_inbox_under_another_key_is_refused_by_every_node() {
    let p = Pair::boot(100, 0).await;
    granted_both_ways(&p.a, &p.b).await;
    let sent = p.a.send(&p.b, 10).await;
    assert!(sent.success, "{:?}", sent.error_message);

    p.a.enter();
    let route: String = {
        let binding = client_db::get_connection().expect("conn");
        let conn = binding.lock().expect("the store lock");
        conn.query_row(
            "SELECT o.routing_address FROM sender_outbox o JOIN sender_online_proposal p \
             ON p.relationship_key = o.relationship_key AND p.commitment = o.commitment \
             WHERE p.token_id != '' ORDER BY o.rowid DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .expect("the payment's route")
    };
    let derived = client_db::inbox_route(&route)
        .expect("the route store")
        .expect("A derived the route");
    assert!(
        derived.lock_public_key.is_some(),
        "the payment's inbox is bound to B's lock"
    );
    let address = <[u8; 32]>::try_from(
        crate::util::text_id::decode_base32_crockford(&route)
            .expect("the route decodes")
            .as_slice(),
    )
    .expect("a 32-byte route");
    let stranger = dsm::crypto::sphincs::generate_keypair(WRITE_KEY_VARIANT).expect("a key");
    let message_id: [u8; 16] = rand::random();
    let write = dsm::core::relationship_write_grant::self_granted_spool_write(
        &stranger,
        &[0x5A; 32],
        &derived.route_digest,
        &address,
        &message_id,
        b"a stranger's bytes",
    )
    .expect("a signed write");
    for node in &p.nodes.nodes {
        let member = crate::sdk::storage_node_sdk::member_client(&node.member_id, &node.endpoint)
            .expect("a member client");
        let answer = member
            .post(format!("{}/api/v2/b0x/submit", node.endpoint))
            .header("Content-Type", "application/octet-stream")
            .header("x-dsm-recipient", route.as_str())
            .header(
                "x-dsm-message-id",
                crate::util::text_id::encode_base32_crockford(&message_id),
            )
            .body(write.clone())
            .send()
            .await
            .expect("the member answers");
        assert_eq!(
            answer.status(),
            reqwest::StatusCode::FORBIDDEN,
            "{} took a write under another key",
            node.endpoint
        );
    }

    for _ in 0..6 {
        p.b.sync().await;
        p.a.sync().await;
        if p.b.era_balance() == 10 {
            break;
        }
    }
    assert_eq!(p.b.era_balance(), 10, "B took A's payment");
}
