// SPDX-License-Identifier: MIT OR Apache-2.0
//! MR-DSM-0101: every correct implementation generates exactly the same bytes
//! for the same object. The CCB and SoFi objects have their independent
//! encoders (`ccb_conformance`, `sofi_v8_independent`); these are the others a
//! verifier hashes or signs: a route entry, whose exact bytes every seat
//! holds and every arrival record commits; the online transfer request; a
//! transfer's canonical operation bytes, which SIG A signs and the tip hashes;
//! and a step receipt's canonical commit form, which both parties sign and
//! the receipt commitment hashes.
//! Each is encoded here from its wire definition — `proto/dsm_app.proto`, and
//! the canonical layout of `Operation::to_bytes` — with no production encoder,
//! and compared byte for byte.

use dsm::route_chain::{ChainSlot, RouteEntry};
use dsm::storage_cell::ArrivalRecord;
use prost::Message;

/// A protobuf varint.
fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn tag(field: u32, wire_type: u8, out: &mut Vec<u8>) {
    varint((u64::from(field) << 3) | u64::from(wire_type), out);
}

/// A length-delimited field, written even when empty: a set submessage.
fn delimited(field: u32, bytes: &[u8], out: &mut Vec<u8>) {
    tag(field, 2, out);
    varint(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// A proto3 `bytes` field: nothing when empty.
fn bytes_field(field: u32, bytes: &[u8], out: &mut Vec<u8>) {
    if !bytes.is_empty() {
        delimited(field, bytes, out);
    }
}

/// A proto3 integer field: nothing when zero.
fn uint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    if value != 0 {
        tag(field, 0, out);
        varint(value, out);
    }
}

/// `ArrivalRecordV1 { member_id = 1, namespace = 2, key = 3, index = 4,
/// running_hash = 5 }`.
fn arrival_record(record: &ArrivalRecord) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(1, &record.member_id, &mut out);
    bytes_field(2, &record.namespace, &mut out);
    bytes_field(3, &record.key, &mut out);
    uint_field(4, record.index, &mut out);
    bytes_field(5, &record.running_hash, &mut out);
    out
}

/// `ChainSlotV1 { oneof kind { link = 1; taken = 2; no_response = 3 } }`.
fn chain_slot(slot: &ChainSlot) -> Vec<u8> {
    let mut out = Vec::new();
    match slot {
        ChainSlot::Link(record) => delimited(1, &arrival_record(record), &mut out),
        ChainSlot::Taken(record) => delimited(2, &arrival_record(record), &mut out),
        ChainSlot::NoResponse => delimited(3, &[], &mut out),
    }
    out
}

/// `RouteEntryV1 { namespace = 1, key = 2, value = 3, seat_member_id = 4,
/// position = 5, repeated chain = 6 }`.
fn route_entry(entry: &RouteEntry) -> Vec<u8> {
    let mut out = Vec::new();
    bytes_field(1, &entry.namespace, &mut out);
    bytes_field(2, &entry.key, &mut out);
    bytes_field(3, &entry.value, &mut out);
    bytes_field(4, &entry.seat, &mut out);
    uint_field(5, entry.position as u64, &mut out);
    for slot in &entry.chain {
        delimited(6, &chain_slot(slot), &mut out);
    }
    out
}

fn record(member: &[u8], index: u64, fill: u8) -> ArrivalRecord {
    ArrivalRecord {
        member_id: member.to_vec(),
        namespace: b"DSM/test/wire".to_vec(),
        key: [0x4B; 32],
        index,
        running_hash: [fill; 32],
    }
}

#[test]
fn a_route_entry_is_the_same_bytes_from_an_independent_encoder() {
    let entry = RouteEntry {
        namespace: b"DSM/test/wire".to_vec(),
        key: [0x4B; 32],
        value: b"the value every seat holds".to_vec(),
        seat: b"member-3".to_vec(),
        position: 3,
        chain: vec![
            ChainSlot::Link(record(b"member-0", 1, 0xA0)),
            ChainSlot::NoResponse,
            ChainSlot::Taken(record(b"member-2", 7, 0xA2)),
        ],
    };
    let independent = route_entry(&entry);
    assert_eq!(entry.encode(), independent);
    assert_eq!(RouteEntry::decode(&independent), Some(entry));

    let leader = RouteEntry {
        namespace: b"DSM/test/wire".to_vec(),
        key: [0x4B; 32],
        value: b"v".to_vec(),
        seat: b"member-0".to_vec(),
        position: 0,
        chain: Vec::new(),
    };
    assert_eq!(leader.encode(), route_entry(&leader));
}

/// `OnlineTransferRequest { signature = 5, canonical_operation_bytes = 11,
/// sender_economic_position = 13, sender_debit_mutation_index = 14,
/// transfer_terms = 15 }`.
#[test]
fn an_online_transfer_request_is_the_same_bytes_from_an_independent_encoder() {
    let request = dsm::types::proto::OnlineTransferRequest {
        signature: vec![0x51; 40],
        canonical_operation_bytes: vec![0x52; 70],
        sender_economic_position: 300,
        sender_debit_mutation_index: 2,
        transfer_terms: vec![0x53; 20],
    };
    let mut independent = Vec::new();
    bytes_field(5, &request.signature, &mut independent);
    bytes_field(11, &request.canonical_operation_bytes, &mut independent);
    uint_field(13, request.sender_economic_position, &mut independent);
    uint_field(
        14,
        u64::from(request.sender_debit_mutation_index),
        &mut independent,
    );
    bytes_field(15, &request.transfer_terms, &mut independent);
    assert_eq!(request.encode_to_vec(), independent);
}

/// `Operation::Transfer`'s canonical bytes: tag 37, then each field as a
/// little-endian u32 length and its bytes — the recipient, the balance's 16
/// canonical bytes (value then locked, little-endian u64s), the policy
/// commitment, the terms commitment, the token's committed policy bytes, the
/// signature — and no authority-policy tail when there is none.
#[test]
fn a_transfers_canonical_bytes_are_the_same_from_an_independent_encoder() {
    let put = |bytes: &[u8], out: &mut Vec<u8>| {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    };
    let operation = dsm::types::operations::Operation::Transfer {
        to_device_id: vec![0x61; 32],
        amount: dsm::types::token_types::Balance::amount(1_234),
        policy_commit: [0x62; 32],
        token_policy: vec![0x65; 7],
        terms_commitment: [0x63; 32],
        signature: vec![0x64; 9],
        authority_policy: None,
    };
    let mut balance = [0u8; 16];
    balance[..8].copy_from_slice(&1_234u64.to_le_bytes());
    let mut independent = vec![37u8];
    put(&[0x61; 32], &mut independent);
    put(&balance, &mut independent);
    put(&[0x62; 32], &mut independent);
    put(&[0x63; 32], &mut independent);
    put(&[0x65; 7], &mut independent);
    put(&[0x64; 9], &mut independent);
    assert_eq!(operation.to_bytes(), independent);
}

/// A step receipt's canonical commit form (whitepaper §4.2.1, `ReceiptCommit`
/// in `proto/dsm_app.proto`): `genesis = 1`, `devid_a = 2`, `devid_b = 3`,
/// `parent_tip = 4`, `child_tip = 5`, `parent_root = 6`, `child_root = 7`,
/// `dev_proof = 10`, `transition_entropy = 21` and `step_writes = 22`, a
/// `StepWriteSet { writes = 1 }` of `StepWrite { relationship = 1 {},
/// path_heights = 4, path_siblings = 5 }`. The signatures, certificates,
/// ephemeral keys and Kyber ciphertexts are wire-only and never in it.
#[test]
fn a_receipts_canonical_bytes_are_the_same_from_an_independent_encoder() {
    use dsm::merkle::smt_path::EncodedPath;
    use dsm::types::receipt_types::{ReceiptLeaf, ReceiptWrite, StitchedReceiptV2};

    // A path with siblings at heights 0 and 1, in the one canonical form.
    let heights: [u8; 32] = std::array::from_fn(|i| if i == 31 { 0b11 } else { 0x00 });
    let siblings = [[0x71u8; 32], [0x72u8; 32]].concat();
    let receipt = StitchedReceiptV2 {
        genesis: [0x01; 32],
        devid_a: [0x02; 32],
        devid_b: [0x03; 32],
        parent_tip: [0x04; 32],
        child_tip: [0x05; 32],
        parent_root: [0x06; 32],
        child_root: [0x07; 32],
        transition_entropy: [0x21; 32],
        step_writes: vec![ReceiptWrite {
            leaf: ReceiptLeaf::Relationship,
            path: EncodedPath {
                explicit_heights: heights,
                siblings: siblings.clone(),
            },
        }],
        dev_proof: vec![0x10; 48],
        sig_a: vec![0x12; 40],
        sig_b: vec![0x13; 40],
        ek_cert_a: vec![0x14; 8],
        ek_cert_b: vec![0x15; 8],
        ek_pk_a: vec![0x16; 8],
        ek_pk_b: vec![0x17; 8],
        kyber_ct_a: vec![0x18; 8],
        kyber_ct_b: vec![0x19; 8],
    };

    let mut write = Vec::new();
    delimited(1, &[], &mut write);
    bytes_field(4, &heights, &mut write);
    bytes_field(5, &siblings, &mut write);
    let mut write_set = Vec::new();
    delimited(1, &write, &mut write_set);
    let mut independent = Vec::new();
    for (field, value) in [
        (1, [0x01u8; 32]),
        (2, [0x02; 32]),
        (3, [0x03; 32]),
        (4, [0x04; 32]),
        (5, [0x05; 32]),
        (6, [0x06; 32]),
        (7, [0x07; 32]),
    ] {
        bytes_field(field, &value, &mut independent);
    }
    bytes_field(10, &[0x10; 48], &mut independent);
    bytes_field(21, &[0x21; 32], &mut independent);
    delimited(22, &write_set, &mut independent);

    let canonical = match receipt.to_canonical_protobuf() {
        Ok(bytes) => bytes,
        Err(e) => panic!("the receipt's canonical form: {e}"),
    };
    assert_eq!(canonical, independent);
}
