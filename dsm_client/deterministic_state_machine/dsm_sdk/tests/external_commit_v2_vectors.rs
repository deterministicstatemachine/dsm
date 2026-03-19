// SPDX-License-Identifier: MIT OR Apache-2.0
//
// ExternalCommit v2 vector suite (strict, deterministic)
// - No legacy `source` string
// - commit_id = H(source_id || payload || evidence_hash) via canonical core implementation
// - v1 bytes rejected
// - NFC routing guard rejects mismatched commit_id
//
// NOTE: This suite is intentionally "vector-like" but does NOT hardcode expected digests,
// because the canonical commit_id function (domain separation, length framing, etc.) must be
// the single source of truth. What we lock in is: determinism, sensitivity, and rejection
// of legacy encodings.
//
// Run: cargo test -p dsm_sdk --test external_commit_v2_vectors

#![forbid(unsafe_code)]
#![allow(clippy::disallowed_methods)]

use prost::Message;

use dsm::commitments::{create_external_commitment, external_evidence_hash, ExternalCommitment};
use dsm_sdk::sdk::external_commitment_sdk::ExternalCommitmentSdk;
use dsm_sdk::wire::pb;

// ----------------------------- Fixtures --------------------------------------
// 32-byte canonical source_id fixtures (base32-crockford, no padding).
// These are "nice" deterministic bytes; they are not secrets.
fn source_id_a() -> [u8; 32] {
    [0xA5u8; 32]
}
fn source_id_b() -> [u8; 32] {
    [0x11u8; 32]
}

fn payload_small() -> Vec<u8> {
    // Deterministic payload bytes (not hex)
    vec![1u8, 2u8, 3u8, 4u8, 5u8, 250u8, 251u8, 252u8]
}
fn payload_empty() -> Vec<u8> {
    Vec::new()
}
fn payload_large() -> Vec<u8> {
    // Deterministic pseudo-pattern; still deterministic across platforms.
    let mut v = Vec::with_capacity(4096);
    for i in 0u32..4096u32 {
        v.push((i.wrapping_mul(73).wrapping_add(41) & 0xFF) as u8);
    }
    v
}

fn evidence_none() -> Option<pb::Evidence> {
    None
}

fn evidence_preimage() -> pb::Evidence {
    // EvidencePreimage with deterministic bytes
    // (keeps this vector suite independent from any external signing infra)
    pb::Evidence {
        kind: Some(pb::evidence::Kind::Preimage(pb::EvidencePreimage {
            preimage: payload_small(),
        })),
    }
}

fn evidence_bytes(ev: Option<&pb::Evidence>) -> Vec<u8> {
    ev.map(|e| e.encode_to_vec()).unwrap_or_default()
}

fn compute_commit_id_v2(
    source_id: &[u8; 32],
    payload: &[u8],
    evidence: Option<&pb::Evidence>,
) -> [u8; 32] {
    let ev_bytes = evidence_bytes(evidence);
    let ev_hash = external_evidence_hash(&ev_bytes);
    create_external_commitment(payload, source_id, &ev_hash)
}

fn compute_commit_id_v2_bytes(
    source_id: &[u8; 32],
    payload: &[u8],
    evidence_bytes: &[u8],
) -> [u8; 32] {
    let ev_hash = external_evidence_hash(evidence_bytes);
    create_external_commitment(payload, source_id, &ev_hash)
}

fn setup_test() {
    dsm::core::bridge::reset_bridge_handlers_for_tests();
}

fn flip_one_bit(mut x: Vec<u8>) -> Vec<u8> {
    if x.is_empty() {
        x.push(1u8);
        return x;
    }
    x[0] ^= 0b0000_0001;
    x
}

fn flip_one_bit_32(mut x: [u8; 32]) -> [u8; 32] {
    x[0] ^= 0b0000_0001;
    x
}

fn nfc_accepts_commit(
    source_id: &[u8; 32],
    payload: &[u8],
    evidence: Option<&pb::Evidence>,
    commit_id: &[u8; 32],
) -> bool {
    let recomputed = compute_commit_id_v2(source_id, payload, evidence);
    &recomputed == commit_id
}

// ----------------------------- Tests -----------------------------------------

#[test]
fn v2_commit_id_is_deterministic_under_roundtrip_bytes() {
    setup_test();
    let sid = source_id_a();
    let payload = payload_small();
    let ev = Some(evidence_preimage());

    // Compute via canonical function
    let commit_id_1 = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    let commit_id_2 = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    assert_eq!(commit_id_1, commit_id_2, "commit_id must be deterministic");

    // Exercise the v2 SDK serialization
    let sdk = ExternalCommitmentSdk::new(std::collections::HashMap::new());
    let obj = ExternalCommitment::new(payload.clone(), sid, evidence_bytes(ev.as_ref()));
    let bytes = sdk.to_v2_bytes(&obj);

    let obj2 = sdk.from_v2_bytes(&bytes).expect("deserialize v2");
    assert_eq!(
        obj.commit_id, obj2.commit_id,
        "commit_id stable across v2 bytes roundtrip"
    );
    assert_eq!(
        obj.source_id, obj2.source_id,
        "source_id stable across v2 bytes roundtrip"
    );
    assert_eq!(
        obj.payload, obj2.payload,
        "payload stable across v2 bytes roundtrip"
    );

    // Recompute from decoded fields matches embedded commit_id
    let recomputed = compute_commit_id_v2_bytes(&obj2.source_id, &obj2.payload, &obj2.evidence);
    assert_eq!(
        obj2.commit_id, recomputed,
        "embedded commit_id must match recomputation"
    );
}

#[test]
fn v2_commit_id_changes_if_source_id_changes_by_one_bit() {
    setup_test();
    let sid = source_id_a();
    let sid2 = flip_one_bit_32(sid);
    let payload = payload_small();
    let ev = Some(evidence_preimage());

    let a = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    let b = compute_commit_id_v2(&sid2, &payload, ev.as_ref());
    assert_ne!(a, b, "bit flip in source_id must change commit_id");
}

#[test]
fn v2_commit_id_changes_if_payload_changes_by_one_bit() {
    setup_test();
    let sid = source_id_a();
    let payload = payload_small();
    let payload2 = flip_one_bit(payload.clone());
    let ev = Some(evidence_preimage());

    let a = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    let b = compute_commit_id_v2(&sid, &payload2, ev.as_ref());
    assert_ne!(a, b, "bit flip in payload must change commit_id");
}

#[test]
fn v2_commit_id_changes_if_evidence_changes() {
    setup_test();
    let sid = source_id_a();
    let payload = payload_small();

    let a = compute_commit_id_v2(&sid, &payload, evidence_none().as_ref());
    let b = compute_commit_id_v2(&sid, &payload, Some(evidence_preimage()).as_ref());
    assert_ne!(
        a, b,
        "adding evidence must change commit_id (evidence_hash participates)"
    );
}

#[test]
fn v2_accepts_empty_payload_but_still_is_deterministic() {
    setup_test();
    let sid = source_id_b();
    let payload = payload_empty();
    let ev = None;

    let a = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    let b = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    assert_eq!(a, b);

    let sdk = ExternalCommitmentSdk::new(std::collections::HashMap::new());
    let obj = ExternalCommitment::new(payload, sid, evidence_bytes(ev.as_ref()));
    let bytes = sdk.to_v2_bytes(&obj);
    let obj2 = sdk.from_v2_bytes(&bytes).expect("deserialize");

    assert_eq!(obj.commit_id, obj2.commit_id);
}

#[test]
fn v2_handles_large_payload_deterministically() {
    setup_test();
    let sid = source_id_a();
    let payload = payload_large();
    let ev = Some(evidence_preimage());

    let a = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    let b = compute_commit_id_v2(&sid, &payload, ev.as_ref());
    assert_eq!(a, b, "large payload must not introduce nondeterminism");

    let sdk = ExternalCommitmentSdk::new(std::collections::HashMap::new());
    let obj = ExternalCommitment::new(payload, sid, evidence_bytes(ev.as_ref()));
    let bytes = sdk.to_v2_bytes(&obj);
    let obj2 = sdk.from_v2_bytes(&bytes).expect("deserialize");
    assert_eq!(obj.commit_id, obj2.commit_id);
}

#[test]
fn v1_bytes_are_rejected_strictly() {
    setup_test();
    // This is a minimal "poison" v1 buffer. The v2 decoder must reject it.
    let v1_poison = vec![1u8, 0u8, 0u8, 0u8, 0u8, 99u8, 88u8, 77u8];

    let sdk = ExternalCommitmentSdk::new(std::collections::HashMap::new());
    let err = sdk.from_v2_bytes(&v1_poison).unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.to_lowercase().contains("v1")
            || msg.to_lowercase().contains("version")
            || msg.to_lowercase().contains("reject")
            || msg.to_lowercase().contains("too short"),
        "must be a hard reject; got: {msg}"
    );
}

#[test]
fn legacy_source_string_bytes_do_not_set_source_id() {
    setup_test();
    // Field 4 (legacy `source` string) is ignored by v2 decode; source_id must remain unset.
    // Protobuf wire: tag = (field_number << 3) | wire_type = (4 << 3) | 2 = 0x22.
    let legacy_source = b"legacy";
    let mut legacy = vec![0x22, legacy_source.len() as u8];
    legacy.extend_from_slice(legacy_source);

    let decoded = pb::ExternalCommit::decode(legacy.as_slice()).expect("decode legacy bytes");
    assert!(
        decoded
            .source_id
            .as_ref()
            .map(|h| h.v.is_empty())
            .unwrap_or(true),
        "legacy source string must not populate source_id"
    );
}

#[test]
fn nfc_guard_rejects_commit_id_mismatch() {
    setup_test();
    let sid = source_id_a();
    let payload = payload_small();
    let ev = Some(evidence_preimage());

    let good = compute_commit_id_v2(&sid, &payload, ev.as_ref());

    // Forge by flipping one bit of commit_id bytes.
    let mut bad = good;
    bad[0] ^= 0b0000_0001;

    let ok = nfc_accepts_commit(&sid, &payload, ev.as_ref(), &good);
    assert!(ok, "good tuple must be accepted");

    let ok2 = nfc_accepts_commit(&sid, &payload, ev.as_ref(), &bad);
    assert!(!ok2, "mismatched commit_id must be rejected");
}

#[test]
fn envelope_transport_roundtrip_for_external_commit() {
    setup_test();
    // ExternalCommit travels inside Envelope v3; framing is [0x03] || Envelope bytes.
    let sid = source_id_a();
    let payload = payload_small();
    let ev = evidence_preimage();

    let ec = pb::ExternalCommit {
        commit_id: Some(pb::Hash32 { v: vec![0u8; 32] }),
        source_id: Some(pb::Hash32 { v: sid.to_vec() }),
        payload: payload.clone(),
        evidence: Some(ev),
    };

    let op = pb::UniversalOp {
        op_id: Some(pb::Hash32 { v: vec![7u8; 32] }),
        actor: vec![],
        genesis_hash: vec![0u8; 32],
        kind: Some(pb::universal_op::Kind::ExternalCommit(ec)),
    };

    let tx = pb::UniversalTx {
        ops: vec![op],
        atomic: true,
    };

    let env = pb::Envelope {
        version: 3,
        headers: Some(pb::Headers {
            device_id: vec![0u8; 32],
            chain_tip: vec![0u8; 32],
            genesis_hash: vec![0u8; 32],
            seq: 1,
        }),
        message_id: vec![9u8; 16],
        payload: Some(pb::envelope::Payload::UniversalTx(tx)),
    };

    let mut env_bytes = Vec::new();
    env.encode(&mut env_bytes).expect("encode envelope");
    let mut framed = Vec::with_capacity(env_bytes.len() + 1);
    framed.push(0x03);
    framed.extend_from_slice(&env_bytes);

    // Decode framed envelope
    assert_eq!(framed[0], 0x03);
    let decoded = pb::Envelope::decode(&framed[1..]).expect("decode framed envelope v3");
    assert_eq!(decoded.version, 3);
    assert!(matches!(
        decoded.payload,
        Some(pb::envelope::Payload::UniversalTx(_))
    ));

    // Re-encode should be stable across decode/encode
    let mut re = Vec::with_capacity(env_bytes.len() + 1);
    re.push(0x03);
    decoded.encode(&mut re).expect("re-encode envelope");
    assert_eq!(
        framed, re,
        "framed bytes must be stable across decode/encode"
    );
}

#[test]
fn nfc_commit_id_mismatch_rejected_by_bridge() {
    setup_test();
    let sid = dsm::commitments::external_source_id("nfc:recovery");
    let payload = payload_small();
    let ev = evidence_preimage();
    let ev_bytes = ev.encode_to_vec();
    let ev_hash = external_evidence_hash(&ev_bytes);
    let mut commit_id = create_external_commitment(&payload, &sid, &ev_hash);
    commit_id[0] ^= 0x01; // break

    let ec = pb::ExternalCommit {
        commit_id: Some(pb::Hash32 {
            v: commit_id.to_vec(),
        }),
        source_id: Some(pb::Hash32 { v: sid.to_vec() }),
        payload: payload.clone(),
        evidence: Some(ev),
    };

    let op = pb::UniversalOp {
        op_id: Some(pb::Hash32 { v: vec![7u8; 32] }),
        actor: vec![],
        genesis_hash: vec![0u8; 32],
        kind: Some(pb::universal_op::Kind::ExternalCommit(ec)),
    };

    let tx = pb::UniversalTx {
        ops: vec![op],
        atomic: true,
    };

    let env = pb::Envelope {
        version: 3,
        headers: Some(pb::Headers {
            device_id: vec![0u8; 32],
            chain_tip: vec![0u8; 32],
            genesis_hash: vec![0u8; 32],
            seq: 1,
        }),
        message_id: vec![9u8; 16],
        payload: Some(pb::envelope::Payload::UniversalTx(tx)),
    };

    let resp_bytes = dsm::core::bridge::handle_envelope_universal(&env.encode_to_vec());
    let resp = pb::Envelope::decode(resp_bytes.as_slice()).expect("decode response");
    match resp.payload {
        Some(pb::envelope::Payload::UniversalRx(rx)) => {
            assert_eq!(rx.results.len(), 1);
            let err = rx.results[0].error.as_ref().expect("error must be set");
            assert_eq!(err.code, 400);
            assert!(err.message.to_lowercase().contains("commit_id"));
        }
        other => panic!("expected UniversalRx, got {:?}", other),
    }
}
