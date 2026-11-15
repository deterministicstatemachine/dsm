// SPDX-License-Identifier: MIT OR Apache-2.0

//! A relationship's first inbox against someone who is neither of its two
//! devices (DSM Amendment A34), on storage nodes.
//!
//! The first inbox of a relationship is the open address of a route digest
//! that the two devices' public identities derive: each one's genesis and
//! device id, and the relationship's first tip, a hash of the same four
//! values. A member fixes the address's key from the first write stored
//! there. Everything here is a production route on the device that takes it,
//! and the third party uses the member's own submit route, as any client.

use dsm::core::bilateral_transaction_manager::initial_relationship_chain_tip;
use dsm::core::relationship_write_grant::self_granted_spool_write;
use dsm::crypto::sphincs::{generate_keypair_from_seed, SphincsVariant};
use dsm::crypto::spool_address::{inbox_route_digest, open_inbox_address_bytes};
use serial_test::serial;

use crate::storage::client_db::RelationshipState;
use crate::test_support::two_device::{Pair, TestDevice};

/// What a member answered one submit.
async fn submit(
    member: &crate::sdk::storage_set::StorageMember,
    address: &[u8; 32],
    message_id: &[u8; 16],
    write: Vec<u8>,
) -> reqwest::StatusCode {
    crate::sdk::storage_node_sdk::member_client(&member.member_id, &member.endpoint)
        .expect("a client of the member")
        .post(format!("{}/api/v2/b0x/submit", member.endpoint))
        .header("Content-Type", "application/protobuf")
        .header(
            "x-dsm-message-id",
            crate::util::text_id::encode_base32_crockford(message_id),
        )
        .header(
            "x-dsm-recipient",
            crate::util::text_id::encode_base32_crockford(address),
        )
        .body(write)
        .send()
        .await
        .expect("the member answers")
        .status()
}

/// One write, under a key of the third party's own, at the first inbox
/// `recipient` reads on its relationship with `writer`, put at every member
/// of the set. The address comes from the two devices' genesis and device
/// ids alone. What each member answered.
async fn write_first_at_the_first_inbox(
    set: &crate::sdk::storage_set::StorageSet,
    recipient: &TestDevice,
    writer: &TestDevice,
) -> Vec<reqwest::StatusCode> {
    let own_key = generate_keypair_from_seed(SphincsVariant::SPX256f, &[0x66; 32])
        .expect("a key of the third party's own");
    let first_tip = initial_relationship_chain_tip(
        &recipient.device_id,
        &recipient.genesis,
        &writer.device_id,
        &writer.genesis,
    );
    let route = inbox_route_digest(&recipient.genesis, &recipient.device_id, &first_tip);
    let address = open_inbox_address_bytes(&route);
    let message_id = [0x66u8; 16];
    let write = self_granted_spool_write(
        &own_key,
        &[0x66; 32],
        &route,
        &address,
        &message_id,
        b"bytes of the third party's choosing",
    )
    .expect("a write the third party signs with its own key");
    let mut answers = Vec::new();
    for member in set.members() {
        answers.push(submit(member, &address, &message_id, write.clone()).await);
    }
    answers
}

/// Two devices that have never been contacts must be able to become
/// contacts, whatever anyone else wrote first.
///
/// A and B establish a relationship on the set, as the harness boots them.
/// C and D boot on the same set and have not added each other. A third
/// party, holding no key of either and knowing only the genesis and device
/// id of each, writes once at C's first inbox for D and once at D's first
/// inbox for C, under a key of its own. Then C and D add each other.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_third_partys_first_write_does_not_keep_two_devices_from_becoming_contacts() {
    let p = Pair::boot(0, 0).await;
    assert_eq!(
        (p.a.relationship_state(&p.b), p.b.relationship_state(&p.a)),
        (
            RelationshipState::Established,
            RelationshipState::Established
        ),
        "two devices nobody wrote ahead of establish on this set"
    );

    let mut c = TestDevice::create("C", 0x0C);
    let mut d = TestDevice::create("D", 0x0D);
    c.boot(&p.fleet).await;
    d.boot(&p.fleet).await;

    c.enter();
    let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
        .expect("the pinned set");
    let at_ds_inbox = write_first_at_the_first_inbox(&set, &d, &c).await;
    let at_cs_inbox = write_first_at_the_first_inbox(&set, &c, &d).await;
    assert!(
        at_ds_inbox
            .iter()
            .chain(&at_cs_inbox)
            .all(|answer| *answer == reqwest::StatusCode::NO_CONTENT),
        "the members did not all store the third party's writes: {at_ds_inbox:?} / {at_cs_inbox:?}"
    );

    c.add_contact(&d).await;
    d.add_contact(&c).await;
    let mut said: Vec<String> = Vec::new();
    for _ in 0..8 {
        let (mine, theirs) = (c.sync().await, d.sync().await);
        said = mine
            .errors
            .iter()
            .map(|e| format!("C: {e}"))
            .chain(theirs.errors.iter().map(|e| format!("D: {e}")))
            .collect();
    }
    assert_eq!(
        (c.relationship_state(&d), d.relationship_state(&c)),
        (
            RelationshipState::Established,
            RelationshipState::Established
        ),
        "one write from a third party at each first inbox kept C and D from becoming contacts. \
         Their last syncs said: {}",
        said.join(" | ")
    );
}
