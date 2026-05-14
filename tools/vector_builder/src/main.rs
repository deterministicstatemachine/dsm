use anyhow::{Context, Result};
use dsm::types::proto as gp;
use prost::Message;
use std::fs;
use std::path::{Path, PathBuf};

const CASES: &[(&str, &str)] = &[
    ("case_0001_proof_cap_over", "PROOF_TOO_LARGE"),
    ("case_0002_smt_empty_root_ok", "ACCEPT"),
    ("case_0003_smt_empty_root_bad", "INVALID_PROOF"),
    ("case_0004_devtree_empty_root_ok", "ACCEPT"),
    ("case_0005_devtree_single_leaf_ok", "ACCEPT"),
    (
        "case_0006_modal_conflict_pending_online",
        "MODAL_CONFLICT_PENDING_ONLINE",
    ),
    ("case_0007_force_missing_witness", "MISSING_WITNESS"),
    ("case_0008_force_storage_error", "STORAGE_ERROR"),
];

fn main() -> Result<()> {
    let repo_root = repo_root();

    let targets = vec![
        repo_root.join("tests/vectors/v1"),
        repo_root.join("dsm_client/deterministic_state_machine/dsm/tests/vectors/v1"),
        repo_root.join("dsm_client/deterministic_state_machine/dsm_sdk/tests/vectors/v1"),
        repo_root.join("dsm_client/android/app/src/androidTest/assets/vectors/v1"),
    ];

    for (case_id, expected) in CASES {
        let request = build_case_request(case_id)?;
        for root in &targets {
            write_case(root, case_id, expected, &request)?;
        }
    }

    write_manifest(&repo_root.join("dsm_client/android/app/src/androidTest/assets/vectors/v1"))?;

    println!("vector corpus generated: {} cases", CASES.len());
    Ok(())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .ok_or("repo root not found")
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn write_case(root: &Path, case_id: &str, expected: &str, request: &[u8]) -> Result<()> {
    let case_dir = root.join(case_id);
    fs::create_dir_all(&case_dir).with_context(|| format!("create {}", case_dir.display()))?;

    let expected_path = case_dir.join("expected.kv");
    let expected_body = if expected == "PROOF_TOO_LARGE" {
        format!(
            "# Stable expected outcome for this case.\ncode={}\n",
            expected
        )
    } else {
        format!("code={}\n", expected)
    };
    fs::write(&expected_path, expected_body)
        .with_context(|| format!("write {}", expected_path.display()))?;

    let request_path = case_dir.join("request.bin");
    fs::write(&request_path, request)
        .with_context(|| format!("write {}", request_path.display()))?;

    Ok(())
}

fn write_manifest(root: &Path) -> Result<()> {
    let mut lines = String::new();
    for (case_id, _) in CASES {
        lines.push_str(case_id);
        lines.push('\n');
    }
    let path = root.join("manifest.txt");
    fs::write(&path, lines).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn build_case_request(case_id: &str) -> Result<Vec<u8>> {
    match case_id {
        "case_0006_modal_conflict_pending_online" => {
            build_vector_envelope("vector.modal_conflict_pending_online", None, 0)
        }
        "case_0007_force_missing_witness" => {
            let receipt = build_receipt_commit(case_id)?;
            let mut body = Vec::with_capacity(receipt.encoded_len());
            receipt.encode(&mut body)?;
            build_vector_envelope("vector.verify_proofs.v1", Some(body), 1)
        }
        "case_0008_force_storage_error" => {
            let receipt = build_receipt_commit(case_id)?;
            let mut body = Vec::with_capacity(receipt.encoded_len());
            receipt.encode(&mut body)?;
            build_vector_envelope("vector.verify_proofs.v1", Some(body), 2)
        }
        _ => {
            let receipt = build_receipt_commit(case_id)?;
            let mut body = Vec::with_capacity(receipt.encoded_len());
            receipt.encode(&mut body)?;
            build_vector_envelope("vector.verify_proofs.v1", Some(body), 0)
        }
    }
}

fn build_vector_envelope(method: &str, body: Option<Vec<u8>>, seq: u64) -> Result<Vec<u8>> {
    let args = body.map(|b| gp::ArgPack {
        schema_hash: None,
        codec: gp::Codec::Proto as i32,
        body: b,
    });

    let invoke = gp::Invoke {
        program: None,
        method: method.to_string(),
        args,
        pre_state_hash: Some(gp::Hash32 { v: vec![0u8; 32] }),
        post_state_hash: Some(gp::Hash32 { v: vec![0u8; 32] }),
        cosigners: Vec::new(),
        evidence: None,
        nonce: Some(gp::Hash16 { v: vec![0u8; 16] }),
    };

    let op = gp::UniversalOp {
        op_id: Some(gp::Hash32 { v: vec![7u8; 32] }),
        actor: vec![1u8; 32],
        genesis_hash: vec![2u8; 32],
        kind: Some(gp::universal_op::Kind::Invoke(invoke)),
    };

    let tx = gp::UniversalTx {
        ops: vec![op],
        atomic: true,
    };

    let envelope = gp::Envelope {
        version: 3,
        headers: Some(gp::Headers {
            device_id: vec![3u8; 32],
            chain_tip: vec![4u8; 32],
            genesis_hash: vec![5u8; 32],
            seq,
        }),
        message_id: vec![6u8; 16],
        payload: Some(gp::envelope::Payload::UniversalTx(tx)),
    };

    Ok(envelope.encode_to_vec())
}

fn build_receipt_commit(case_id: &str) -> Result<gp::ReceiptCommit> {
    let devid_a = [9u8; 32];
    let devid_b = [8u8; 32];
    let parent_tip = [1u8; 32];
    let child_tip = [2u8; 32];
    let zero_root = [0u8; 32];
    let nonzero_root = [1u8; 32];

    let empty_dev_root = dsm::common::device_tree::empty_root();
    let (parent_root, child_root, rel_parent, rel_child, dev_root, dev_proof) = match case_id {
        "case_0001_proof_cap_over" => (
            zero_root,
            zero_root,
            vec![0u8; dsm::verification::proof_primitives::MAX_PROOF_BYTES + 1],
            Vec::new(),
            empty_dev_root,
            Vec::new(),
        ),
        "case_0002_smt_empty_root_ok" => (
            zero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            empty_dev_root,
            Vec::new(),
        ),
        "case_0003_smt_empty_root_bad" => (
            nonzero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            empty_dev_root,
            Vec::new(),
        ),
        "case_0004_devtree_empty_root_ok" => (
            zero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            empty_dev_root,
            Vec::new(),
        ),
        "case_0005_devtree_single_leaf_ok" => (
            zero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            dsm::common::device_tree::hash_leaf(&devid_a),
            Vec::new(),
        ),
        "case_0007_force_missing_witness" => (
            zero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            empty_dev_root,
            Vec::new(),
        ),
        "case_0008_force_storage_error" => (
            zero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            empty_dev_root,
            Vec::new(),
        ),
        _ => (
            zero_root,
            zero_root,
            Vec::new(),
            Vec::new(),
            zero_root,
            Vec::new(),
        ),
    };

    Ok(gp::ReceiptCommit {
        genesis: dev_root.to_vec(),
        devid_a: devid_a.to_vec(),
        devid_b: devid_b.to_vec(),
        parent_tip: parent_tip.to_vec(),
        child_tip: child_tip.to_vec(),
        parent_root: parent_root.to_vec(),
        child_root: child_root.to_vec(),
        rel_proof_parent: rel_parent,
        rel_proof_child: rel_child,
        rel_replace_witness: Vec::new(),
        dev_proof,
        sig_a: vec![],
        sig_b: vec![],
        // Envelope-only fields (whitepaper §11.1 ek-cert chain + per-step EK
        // pubkeys). Not part of the canonical commit form per §4.2.1; left
        // empty for vector generation since vector_builder produces
        // deterministic test fixtures independent of session cert chains
        // and per-step EK derivation.
        ek_cert_a: vec![],
        ek_cert_b: vec![],
        ek_pk_a: vec![],
        ek_pk_b: vec![],
        // Per-step Kyber ciphertexts (whitepaper §11) — wire-only.
        kyber_ct_a: vec![],
        kyber_ct_b: vec![],
    })
}
