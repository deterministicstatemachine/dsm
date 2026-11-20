// SPDX-License-Identifier: MIT OR Apache-2.0

//! A device's directory cell against someone who holds none of its keys, on
//! storage nodes.
//!
//! A device's directory entry lives at a cell anyone can derive from its
//! genesis and device id, the two values its contact code shows, and a member
//! keeps whatever it is given there. "A squatter's junk fails the check and
//! is ignored, and no one can lock a device out" (`dsm::core::identity::
//! directory`). Every step here is a production route on the device that
//! takes it, and the third party uses the member's own cell route, as any
//! client.

use dsm::core::identity::directory::{
    directory_cell_key, DirectoryEntry, DirectoryEntryBody, AK_PUBLIC_KEY_LEN, DIRECTORY_NAMESPACE,
    FIRST_INBOX_LOCK_LEN, KYBER_PUBLIC_KEY_LEN,
};
use serial_test::serial;

use crate::test_support::two_device::{Pair, TestDevice};

/// What this device keeps of one member's read of a cell at most
/// (`route_seats::HELD_LOG_BUDGET`).
const ONE_MEMBERS_READ: usize = 8 * 1024 * 1024;

/// Entries naming `device` that nobody signed: its genesis and device id,
/// and bytes of the third party's choosing everywhere else. Distinct ones,
/// each near the largest value a cell takes, until they pass `over` bytes in
/// all.
fn entries_nobody_signed(device: &TestDevice, over: usize) -> Vec<Vec<u8>> {
    let mut made = Vec::new();
    let mut bytes = 0usize;
    while bytes <= over {
        let entry = DirectoryEntry {
            body: DirectoryEntryBody {
                genesis: device.genesis,
                device_id: device.device_id,
                ak_public_key: vec![0x5A; AK_PUBLIC_KEY_LEN],
                att_a: [0x5A; 32],
                kyber_public_key: vec![0x5A; KYBER_PUBLIC_KEY_LEN],
                first_inbox_lock_public_key: vec![0x5A; FIRST_INBOX_LOCK_LEN],
                cell_lock_public_key: vec![0xC5; dsm::owned_cell::CELL_LOCK_LEN],
                counter: made.len() as u64,
                authority_position: [0x5A; 32],
                authority_evidence: vec![0xEE; 320 * 1024],
            },
            signature: vec![0xA5; 1024],
        }
        .encode();
        bytes += entry.len();
        made.push(entry);
    }
    made
}

/// No one can lock a device out of its own directory cell.
///
/// A pays B once, as any two contacts do. A third party, holding no key of
/// B's and knowing only B's genesis and device id, puts a little over one
/// member's read budget of entries naming B that nobody signed at B's
/// directory cell, on every member, through the member's ordinary cell
/// route. A must still be able to pay B, and a device that has B's contact
/// code must still be able to add B.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn a_third_partys_unsigned_entries_do_not_lock_a_device_out() {
    let p = Pair::boot(100, 0).await;
    let first = p.a.send(&p.b, 10).await;
    assert!(first.success, "{:?}", first.error_message);
    assert!(p.b.sync().await.success);
    assert!(p.a.sync().await.success);
    assert_eq!(
        p.b.era_balance(),
        10,
        "B is paid before anyone writes at its cell"
    );

    p.a.enter();
    let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
        .expect("the pinned set");
    let client = crate::sdk::storage_node_sdk::SetClient::new(&set).expect("a client of the set");
    let cell = directory_cell_key(&p.b.genesis, &p.b.device_id);
    let unsigned = entries_nobody_signed(&p.b, ONE_MEMBERS_READ);
    // B's directory cell is B's (owner ruling, 2026-11-19): no member keeps
    // a write B's AK did not sign there.
    for entry in &unsigned {
        assert_eq!(
            client.put_cell(DIRECTORY_NAMESPACE, &cell, entry).await,
            0,
            "no member keeps a third party's write in B's cell"
        );
    }

    // A device that holds B's contact code adds B.
    let mut c = TestDevice::create("C", 0x0C);
    c.boot(&p.fleet).await;
    let added = c
        .invoke(
            "contacts.addManual",
            &dsm::types::proto::ContactManualAddRequest {
                alias: "B".to_string(),
                device_id: p.b.device_id.to_vec(),
                genesis_hash: p.b.genesis.to_vec(),
                signing_public_key: p.b.ak_pk.clone(),
                profile: None,
            },
        )
        .await;

    // A pays B again.
    let second = p.a.send(&p.b, 10).await;
    assert!(
        second.success && added.success,
        "{} unsigned entries ({} bytes) from a third party at B's directory cell locked B out. \
         A's payment to B: {:?}. A device adding B from its contact code: {:?}",
        unsigned.len(),
        unsigned.iter().map(Vec::len).sum::<usize>(),
        second.error_message,
        added.error_message
    );
}
