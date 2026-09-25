// SPDX-License-Identifier: Apache-2.0

//! The PR2 evidence formats, adversarially: successor evidence (`sigma_dsm`),
//! the portable acceptance bundle (`sig_b` IS the acceptance), the
//! signer-identity EK ancestry.

#![allow(clippy::disallowed_methods)]

use prost::Message;

use dsm::crypto::ephemeral_key::sign_ek_cert;
use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
use dsm::economic::peer_acceptance::{
    ek_cert_step_addr, verify_peer_transfer_acceptance, AcceptanceParty,
};
use dsm::economic::provenance::PeerLineageFailure;
use dsm::economic::successor_evidence::{
    sign_dsm_successor_evidence, verify_dsm_successor_evidence, SuccessorEvidenceError,
};
use dsm::types::operations::{Operation, TransactionMode};
use dsm::types::proto as generated;
use dsm::types::receipt_types::{
    compute_receipt_b_canonical_target, compute_receipt_challenge_response_target,
    StitchedReceiptV2,
};
use dsm::types::token_types::Balance;

const G_SENDER: [u8; 32] = [0x51; 32];
const DEV_SENDER: [u8; 32] = [0x52; 32];
const DEV_RECIP: [u8; 32] = [0x62; 32];

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn transfer_to(recipient: [u8; 32], amount: u64) -> Operation {
    Operation::Transfer {
        to_device_id: recipient.to_vec(),
        amount: Balance::amount(amount),
        token_id: b"ERA".to_vec(),
        policy_commit: era(),
        mode: TransactionMode::Bilateral,
        nonce: vec![9; 32],
        recipient: Vec::new(),
        to: Vec::new(),
        message: String::new(),
        signature: Vec::new(),
        authority_policy: None,
    }
}

// ── Successor evidence ─────────────────────────────────────────────────────

#[test]
fn successor_evidence_round_trips_and_refuses_tampering() {
    let (ak_pk, ak_sk) = generate_sphincs_keypair().unwrap();
    let op = transfer_to(DEV_RECIP, 40);
    let bytes = sign_dsm_successor_evidence(
        &[0x01; 32],
        &[0x02; 32],
        &DEV_RECIP,
        &op.to_bytes(),
        &[7, 7, 7],
        None,
        &G_SENDER,
        &DEV_SENDER,
        &ak_sk,
    )
    .expect("signable");
    let verified = verify_dsm_successor_evidence(&bytes, &G_SENDER, &DEV_SENDER, &ak_pk)
        .expect("verifies under the signing AK");
    assert_eq!(verified.operation.to_bytes(), op.to_bytes());

    // A DIFFERENT proven AK: signature invalid.
    let (other_pk, _) = generate_sphincs_keypair().unwrap();
    assert_eq!(
        verify_dsm_successor_evidence(&bytes, &G_SENDER, &DEV_SENDER, &other_pk).unwrap_err(),
        SuccessorEvidenceError::SignatureInvalid
    );

    // Tampered carried commitment: the preimage recomputation refuses.
    let mut ev = generated::DsmSuccessorEvidenceV1::decode(bytes.as_slice()).unwrap();
    ev.c_dsm_plus[0] ^= 1;
    assert_eq!(
        verify_dsm_successor_evidence(&ev.encode_to_vec(), &G_SENDER, &DEV_SENDER, &ak_pk)
            .unwrap_err(),
        SuccessorEvidenceError::CommitmentMismatch
    );

    // Substituted operation bytes: the commitment no longer recomputes.
    let mut ev2 = generated::DsmSuccessorEvidenceV1::decode(bytes.as_slice()).unwrap();
    ev2.operation_bytes = transfer_to(DEV_RECIP, 41).to_bytes();
    assert_eq!(
        verify_dsm_successor_evidence(&ev2.encode_to_vec(), &G_SENDER, &DEV_SENDER, &ak_pk)
            .unwrap_err(),
        SuccessorEvidenceError::CommitmentMismatch
    );
}

// ── The acceptance bundle ──────────────────────────────────────────────────

struct AcceptanceFixture {
    bundle_bytes: Vec<u8>,
    sender_ak_pk: Vec<u8>,
    recipient_ak_pk: Vec<u8>,
    transfer_bytes: Vec<u8>,
    child_tip: [u8; 32],
    b_pair: ([u8; 32], [u8; 32]),
    steps: std::collections::HashMap<[u8; 32], Vec<u8>>,
}

/// Build a fully valid acceptance bundle with real keys, both sides at
/// relationship genesis (EK certs signed directly by the AKs).
fn acceptance_fixture() -> AcceptanceFixture {
    let (sender_ak_pk, sender_ak_sk) = generate_sphincs_keypair().unwrap();
    let (recipient_ak_pk, recipient_ak_sk) = generate_sphincs_keypair().unwrap();
    let (ek_pk_a, ek_sk_a) = generate_sphincs_keypair().unwrap();
    let (ek_pk_b, ek_sk_b) = generate_sphincs_keypair().unwrap();

    let op = transfer_to(DEV_RECIP, 40);
    let transfer_bytes = op.to_bytes();
    let parent_tip = [0x71; 32];
    let child_tip = [0x72; 32];

    let mut receipt = StitchedReceiptV2::new(
        G_SENDER,
        DEV_SENDER,
        DEV_RECIP,
        parent_tip,
        child_tip,
        [0x73; 32],
        [0x74; 32],
        Vec::new(),
        Vec::new(),
    );
    receipt.ek_pk_a = ek_pk_a.clone();
    receipt.ek_cert_a = sign_ek_cert(&sender_ak_sk, &ek_pk_a, &parent_tip).unwrap();
    let commitment = receipt.compute_commitment().unwrap();
    let a_target = compute_receipt_challenge_response_target(&commitment, &commitment);
    receipt.sig_a = sphincs_sign(&ek_sk_a, &a_target).unwrap();
    let evidence_a_bytes = receipt.to_full_protobuf().unwrap();

    let request = generated::OnlineTransferRequest {
        signature: sphincs_sign(&sender_ak_sk, &transfer_bytes).unwrap(),
        canonical_operation_bytes: transfer_bytes.clone(),
        receipt_evidence_digest: dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
            &evidence_a_bytes,
        )
        .to_vec(),
        ..Default::default()
    };

    let (b_parent, b_child) = ([0x75; 32], [0x76; 32]);
    let b_target =
        compute_receipt_b_canonical_target(&commitment, &commitment, &b_parent, &b_child);
    let countersign = generated::ReceiptCountersignB {
        commitment: commitment.to_vec(),
        receipt_evidence_digest_a: request.receipt_evidence_digest.clone(),
        sig_b: sphincs_sign(&ek_sk_b, &b_target).unwrap(),
        ek_cert_b: sign_ek_cert(&recipient_ak_sk, &ek_pk_b, &parent_tip).unwrap(),
        ek_pk_b: ek_pk_b.clone(),
        kyber_ct_b: vec![0x0B; 32],
        b_parent_tip: b_parent.to_vec(),
        b_child_tip: b_child.to_vec(),
        recipient_economic_release_addr: Vec::new(),
    };

    let bundle = generated::PeerTransferAcceptanceEvidenceV1 {
        transfer_request_bytes: request.encode_to_vec(),
        receipt_evidence_a_bytes: evidence_a_bytes,
        receipt_countersign_b_bytes: countersign.encode_to_vec(),
        a_prior_step_addr: None,
        b_prior_step_addr: None,
    };
    AcceptanceFixture {
        bundle_bytes: bundle.encode_to_vec(),
        sender_ak_pk,
        recipient_ak_pk,
        transfer_bytes,
        child_tip,
        b_pair: (b_parent, b_child),
        steps: std::collections::HashMap::new(),
    }
}

fn verify_fixture(
    fx: &AcceptanceFixture,
    recipient_devid: [u8; 32],
    expected_transfer: &[u8],
    expected_child: &[u8; 32],
) -> Result<dsm::economic::peer_acceptance::VerifiedAcceptance, PeerLineageFailure> {
    let steps = fx.steps.clone();
    let mut fetch = move |addr: &[u8; 32]| {
        steps
            .get(addr)
            .cloned()
            .ok_or_else(|| PeerLineageFailure::Incomplete("no such EK step in this fixture".into()))
    };
    verify_peer_transfer_acceptance(
        &fx.bundle_bytes,
        &AcceptanceParty {
            devid: DEV_SENDER,
            proven_ak: &fx.sender_ak_pk,
        },
        &AcceptanceParty {
            devid: recipient_devid,
            proven_ak: &fx.recipient_ak_pk,
        },
        expected_transfer,
        expected_child,
        &fx.b_pair,
        &mut fetch,
    )
}

#[test]
fn a_valid_acceptance_bundle_verifies_and_every_binding_is_load_bearing() {
    let fx = acceptance_fixture();
    let ok = verify_fixture(&fx, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip)
        .expect("valid bundle verifies");
    assert_eq!(ok.sender_child_tip, fx.child_tip);

    // Different recipient devid: the receipt names the parties.
    assert!(verify_fixture(&fx, [0x63; 32], &fx.transfer_bytes, &fx.child_tip).is_err());

    // Different expected transfer: not the validated debit's operation.
    let other = transfer_to(DEV_RECIP, 41).to_bytes();
    assert!(verify_fixture(&fx, DEV_RECIP, &other, &fx.child_tip).is_err());

    // Different bilateral step (child tip): acceptance is FOR a step.
    assert!(verify_fixture(&fx, DEV_RECIP, &fx.transfer_bytes, &[0x7F; 32]).is_err());

    // Tampered countersignature: no acceptance.
    let mut bundle =
        generated::PeerTransferAcceptanceEvidenceV1::decode(fx.bundle_bytes.as_slice()).unwrap();
    let mut cs =
        generated::ReceiptCountersignB::decode(bundle.receipt_countersign_b_bytes.as_slice())
            .unwrap();
    cs.sig_b[0] ^= 1;
    bundle.receipt_countersign_b_bytes = cs.encode_to_vec();
    let tampered = AcceptanceFixture {
        bundle_bytes: bundle.encode_to_vec(),
        ..acceptance_clone(&fx)
    };
    assert!(verify_fixture(&tampered, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip).is_err());
}

#[test]
fn the_bundle_cannot_self_select_its_b_side_pair() {
    // Correction 5: the expected B pair comes from the exact recipient
    // successor under validation — a bundle whose countersigned pair is
    // anything else is refused, even though sig_b verifies over the pair the
    // bundle itself declares.
    let fx = acceptance_fixture();
    let wrong = AcceptanceFixture {
        b_pair: ([0x7E; 32], fx.b_pair.1),
        ..acceptance_clone(&fx)
    };
    let err = verify_fixture(&wrong, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip)
        .expect_err("a self-selected pair must be refused");
    assert!(
        matches!(&err, PeerLineageFailure::Invalid(m)
            if m.contains("not the accepted recipient successor's pair")),
        "got: {err:?}"
    );
}

fn acceptance_clone(fx: &AcceptanceFixture) -> AcceptanceFixture {
    AcceptanceFixture {
        bundle_bytes: fx.bundle_bytes.clone(),
        sender_ak_pk: fx.sender_ak_pk.clone(),
        recipient_ak_pk: fx.recipient_ak_pk.clone(),
        transfer_bytes: fx.transfer_bytes.clone(),
        child_tip: fx.child_tip,
        b_pair: fx.b_pair,
        steps: fx.steps.clone(),
    }
}

#[test]
fn ek_ancestry_walks_one_step_and_refuses_unhashed_substitution() {
    // Signer with ONE prior EK step (e.g. after a role reversal or BLE
    // advance): current cert is signed by the PRIOR step's EK, whose own
    // cert chains to the AK.
    let fx = acceptance_fixture();
    let (recipient_ak_pk, recipient_ak_sk) = generate_sphincs_keypair().unwrap();
    let (prior_pk, prior_sk) = generate_sphincs_keypair().unwrap();
    let (ek_pk_b, ek_sk_b) = generate_sphincs_keypair().unwrap();
    let h_prior = [0x41; 32];
    let prior_step = generated::EkCertStepV1 {
        ek_pk: prior_pk.clone(),
        ek_cert: sign_ek_cert(&recipient_ak_sk, &prior_pk, &h_prior).unwrap(),
        h_n: h_prior.to_vec(),
        prior_step_addr: None,
    };
    let prior_bytes = prior_step.encode_to_vec();
    let prior_addr = ek_cert_step_addr(&prior_bytes);

    // Rebuild the countersign under the CHAINED EK.
    let mut bundle =
        generated::PeerTransferAcceptanceEvidenceV1::decode(fx.bundle_bytes.as_slice()).unwrap();
    let receipt =
        StitchedReceiptV2::from_canonical_protobuf(&bundle.receipt_evidence_a_bytes).unwrap();
    let commitment = receipt.compute_commitment().unwrap();
    let (b_parent, b_child) = ([0x75; 32], [0x76; 32]);
    let b_target =
        compute_receipt_b_canonical_target(&commitment, &commitment, &b_parent, &b_child);
    let countersign = generated::ReceiptCountersignB {
        commitment: commitment.to_vec(),
        receipt_evidence_digest_a: dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
            &bundle.receipt_evidence_a_bytes,
        )
        .to_vec(),
        sig_b: sphincs_sign(&ek_sk_b, &b_target).unwrap(),
        ek_cert_b: sign_ek_cert(&prior_sk, &ek_pk_b, &receipt.parent_tip).unwrap(),
        ek_pk_b: ek_pk_b.clone(),
        kyber_ct_b: vec![0x0B; 32],
        b_parent_tip: b_parent.to_vec(),
        b_child_tip: b_child.to_vec(),
        recipient_economic_release_addr: Vec::new(),
    };
    bundle.receipt_countersign_b_bytes = countersign.encode_to_vec();
    bundle.b_prior_step_addr = Some(prior_addr.to_vec());

    let mut chained = acceptance_clone(&fx);
    chained.bundle_bytes = bundle.encode_to_vec();
    chained.recipient_ak_pk = recipient_ak_pk;
    chained.steps.insert(prior_addr, prior_bytes.clone());
    verify_fixture(&chained, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip)
        .expect("one-step chained ancestry verifies");

    // Substituted step bytes that do not hash to the address: refused.
    let mut bad = acceptance_clone(&chained);
    let mut forged = prior_step;
    forged.h_n = vec![0x42; 32];
    bad.steps.insert(prior_addr, forged.encode_to_vec());
    assert!(matches!(
        verify_fixture(&bad, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip),
        Err(PeerLineageFailure::Invalid(_))
    ));
}

// ── The exact peer-debit predicate's refusal clauses ───────────────────────
