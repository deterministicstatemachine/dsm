// SPDX-License-Identifier: MIT OR Apache-2.0
//! MR-DSM-0101: every correct implementation generates exactly the same bytes
//! for the same object. The CCB and SoFi objects have their independent
//! encoders (`ccb_conformance`, `sofi_v8_independent`); these are the others a
//! verifier hashes or signs: a route entry, whose exact bytes every seat
//! holds and every arrival record commits; the online transfer request; and a
//! transfer's canonical operation bytes, which SIG A signs and the tip hashes.
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
    uint_field(14, u64::from(request.sender_debit_mutation_index), &mut independent);
    bytes_field(15, &request.transfer_terms, &mut independent);
    assert_eq!(request.encode_to_vec(), independent);
}

/// `Operation::Transfer`'s canonical bytes: tag 37, then each field as a
/// little-endian u32 length and its bytes — the recipient, the balance's 16
/// canonical bytes (value then locked, little-endian u64s), the policy
/// commitment, the terms commitment, the signature — and no authority-policy
/// tail when there is none.
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
    put(&[0x64; 9], &mut independent);
    assert_eq!(operation.to_bytes(), independent);
}
