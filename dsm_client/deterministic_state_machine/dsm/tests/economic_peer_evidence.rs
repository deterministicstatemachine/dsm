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
        policy_commit: era(),
        token_policy: dsm::core::token::era_policy::era_policy_bytes().to_vec(),
        terms_commitment: dsm::types::operations::TransferTerms {
            token_id: b"ERA".to_vec(),
            nonce: vec![9; 32],
            mode: TransactionMode::Bilateral,
            memo: String::new(),
            salt: vec![0x5A; 32],
        }
        .commitment(),
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
    /// The sender's AK secret: it countersigns a restart of the recipient's
    /// chain on their relationship.
    sender_ak_sk: Vec<u8>,
    recipient_ak_pk: Vec<u8>,
    transfer_bytes: Vec<u8>,
    child_tip: [u8; 32],
    b_pair: ([u8; 32], [u8; 32]),
    steps: std::collections::HashMap<[u8; 32], Vec<u8>>,
    /// Steps the verifier holds as a party: `(signer, addr)` to its key.
    held: std::collections::HashMap<([u8; 32], [u8; 32]), Vec<u8>>,
}

/// The fixture's EK steps, with every fetch recorded.
struct FixtureSteps<'f> {
    fx: &'f AcceptanceFixture,
    fetched: std::cell::RefCell<Vec<[u8; 32]>>,
}

impl dsm::economic::peer_acceptance::EkSteps for FixtureSteps<'_> {
    fn held(
        &self,
        signer: &[u8; 32],
        addr: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, PeerLineageFailure> {
        Ok(self.fx.held.get(&(*signer, *addr)).cloned())
    }

    fn fetch(&self, addr: &[u8; 32]) -> Result<Vec<u8>, PeerLineageFailure> {
        self.fetched.borrow_mut().push(*addr);
        self.fx
            .steps
            .get(addr)
            .cloned()
            .ok_or_else(|| PeerLineageFailure::Incomplete("no such EK step in this fixture".into()))
    }
}

/// The sender's receipt of its first step toward the recipient: its faucet
/// payout on its self-loop, then `op`, both by the real advance, with the
/// receipt the one producer builds from the step.
fn sender_step_receipt(ak_pk: &[u8], op: &Operation, amount: u64) -> StitchedReceiptV2 {
    use dsm::core::bilateral_transaction_manager::compute_smt_key;
    use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};

    use dsm::economic::admission::{
        dsm_operation_digest, PendingAdmissionKind, PendingEconomicAdmission,
    };

    // The claim is advanced as the wallet advances it, carrying its own
    // prepared admission; the head after it carries none.
    let claim = Operation::FaucetClaim {
        reserve_id: dsm::economic::native_reserve::era_reserve_id(
            dsm::economic::register::BETA_NETWORK_ID,
        ),
        generation: 1,
    };
    let prepared = PendingEconomicAdmission::prepared(
        PendingAdmissionKind::DsmBacked,
        1,
        dsm::economic::tree::empty_economic_root(),
        dsm_operation_digest(&claim.to_bytes()),
    );
    let funded = DeviceState::genesis_head(G_SENDER, DEV_SENDER, ak_pk.to_vec())
        .with_pending_economic_admission(Some(prepared))
        .advance(
            compute_smt_key(&DEV_SENDER, &DEV_SENDER),
            DEV_SENDER,
            claim,
            &[BalanceDelta {
                policy_commit: era(),
                direction: BalanceDirection::Credit,
                amount: dsm::economic::native_reserve::ERA_FAUCET_PAYOUT,
            }],
            None,
        )
        .unwrap()
        .new_device_state
        .with_pending_economic_admission(None)
        .establish_relationship(DEV_RECIP)
        .unwrap();
    let outcome = funded
        .advance(
            compute_smt_key(&DEV_SENDER, &DEV_RECIP),
            DEV_RECIP,
            op.clone(),
            &[BalanceDelta {
                policy_commit: era(),
                direction: BalanceDirection::Debit,
                amount,
            }],
            None,
        )
        .unwrap();
    StitchedReceiptV2::of_step(
        G_SENDER,
        DEV_SENDER,
        DEV_RECIP,
        &outcome,
        None,
        &dsm::types::receipt_types::DeviceTreeAcceptanceCommitment::from_root(
            dsm::common::device_tree::DeviceTree::single(DEV_SENDER).root(),
        ),
    )
    .unwrap()
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
    let mut receipt = sender_step_receipt(&sender_ak_pk, &op, 40);
    let parent_tip = receipt.parent_tip;
    let child_tip = receipt.child_tip;
    receipt.ek_pk_a = ek_pk_a.clone();
    receipt.ek_cert_a = sign_ek_cert(&sender_ak_sk, &ek_pk_a, &parent_tip).unwrap();
    let commitment = receipt.compute_commitment().unwrap();
    let a_target = compute_receipt_challenge_response_target(&commitment, &commitment);
    receipt.sig_a = sphincs_sign(&ek_sk_a, &a_target).unwrap();
    let evidence_a_bytes = receipt.to_full_protobuf().unwrap();

    let request = generated::OnlineTransferRequest {
        signature: sphincs_sign(&sender_ak_sk, &transfer_bytes).unwrap(),
        canonical_operation_bytes: transfer_bytes.clone(),
        ..Default::default()
    };

    let (b_parent, b_child) = ([0x75; 32], [0x76; 32]);
    let b_target =
        compute_receipt_b_canonical_target(&commitment, &commitment, &b_parent, &b_child);
    let countersign = generated::ReceiptCountersignB {
        commitment: commitment.to_vec(),
        receipt_evidence_digest_a: dsm::crypto::blake3::domain_hash_bytes(
            dsm::common::domain_tags::TAG_DSM_RECEIPT_EVIDENCE_A,
            &evidence_a_bytes,
        )
        .to_vec(),
        sig_b: sphincs_sign(&ek_sk_b, &b_target).unwrap(),
        ek_cert_b: sign_ek_cert(&recipient_ak_sk, &ek_pk_b, &parent_tip).unwrap(),
        ek_pk_b: ek_pk_b.clone(),
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
        sender_ak_sk,
        recipient_ak_pk,
        transfer_bytes,
        child_tip,
        b_pair: (b_parent, b_child),
        steps: std::collections::HashMap::new(),
        held: std::collections::HashMap::new(),
    }
}

fn verify_fixture(
    fx: &AcceptanceFixture,
    recipient_devid: [u8; 32],
    expected_transfer: &[u8],
    expected_child: &[u8; 32],
) -> Result<dsm::economic::peer_acceptance::VerifiedAcceptance, PeerLineageFailure> {
    verify_fixture_counting(fx, recipient_devid, expected_transfer, expected_child).0
}

/// The verdict, and the EK step addresses the check fetched.
fn verify_fixture_counting(
    fx: &AcceptanceFixture,
    recipient_devid: [u8; 32],
    expected_transfer: &[u8],
    expected_child: &[u8; 32],
) -> (
    Result<dsm::economic::peer_acceptance::VerifiedAcceptance, PeerLineageFailure>,
    Vec<[u8; 32]>,
) {
    let steps = FixtureSteps {
        fx,
        fetched: std::cell::RefCell::new(Vec::new()),
    };
    let verdict = verify_peer_transfer_acceptance(
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
        &steps,
    );
    (verdict, steps.fetched.into_inner())
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
        sender_ak_sk: fx.sender_ak_sk.clone(),
        recipient_ak_pk: fx.recipient_ak_pk.clone(),
        transfer_bytes: fx.transfer_bytes.clone(),
        child_tip: fx.child_tip,
        b_pair: fx.b_pair,
        steps: fx.steps.clone(),
        held: fx.held.clone(),
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
        authority: Some(generated::ek_cert_step_v1::Authority::EkCert(
            sign_ek_cert(&recipient_ak_sk, &prior_pk, &h_prior).unwrap(),
        )),
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

/// The recipient's countersign under an EK certified by `prior_sk`, with the
/// bundle naming `prior_addr` as the recipient's predecessor step.
fn countersigned_after(
    fx: &AcceptanceFixture,
    prior_addr: [u8; 32],
    prior_sk: &[u8],
) -> AcceptanceFixture {
    let (ek_pk_b, ek_sk_b) = generate_sphincs_keypair().unwrap();
    let mut bundle =
        generated::PeerTransferAcceptanceEvidenceV1::decode(fx.bundle_bytes.as_slice()).unwrap();
    let receipt =
        StitchedReceiptV2::from_canonical_protobuf(&bundle.receipt_evidence_a_bytes).unwrap();
    let commitment = receipt.compute_commitment().unwrap();
    let (b_parent, b_child) = fx.b_pair;
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
        ek_cert_b: sign_ek_cert(prior_sk, &ek_pk_b, &receipt.parent_tip).unwrap(),
        ek_pk_b,
        b_parent_tip: b_parent.to_vec(),
        b_child_tip: b_child.to_vec(),
        recipient_economic_release_addr: Vec::new(),
    };
    bundle.receipt_countersign_b_bytes = countersign.encode_to_vec();
    bundle.b_prior_step_addr = Some(prior_addr.to_vec());
    let mut after = acceptance_clone(fx);
    after.bundle_bytes = bundle.encode_to_vec();
    after
}

#[test]
fn a_party_to_the_relationship_checks_one_certificate_from_the_step_it_holds() {
    // Deep in the relationship: the recipient's predecessor step is one the
    // verifier holds as a party. Nothing behind it is in any store here, so
    // a check that went looking for the relationship's history could not
    // complete — this one fetches nothing and verifies the one certificate.
    let fx = acceptance_fixture();
    let (prior_pk, prior_sk) = generate_sphincs_keypair().unwrap();
    let prior_addr = [0x5A; 32];
    let mut deep = countersigned_after(&fx, prior_addr, &prior_sk);
    deep.held.insert((DEV_RECIP, prior_addr), prior_pk.clone());
    let (verdict, fetched) =
        verify_fixture_counting(&deep, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
    verdict.expect("the step after a held step verifies from it");
    assert!(fetched.is_empty(), "fetched {} EK steps", fetched.len());

    // The held key must be the one that certified the current EK.
    let (other_pk, _) = generate_sphincs_keypair().unwrap();
    let mut wrong = acceptance_clone(&deep);
    wrong.held.insert((DEV_RECIP, prior_addr), other_pk);
    assert!(matches!(
        verify_fixture(&wrong, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip),
        Err(PeerLineageFailure::Invalid(_))
    ));

    // A step held in another signer's chain is not this signer's: the check
    // goes looking for the step and, finding none, cannot complete.
    let mut other_signer = acceptance_clone(&deep);
    other_signer.held.clear();
    other_signer.held.insert((DEV_SENDER, prior_addr), prior_pk);
    let (verdict, fetched) =
        verify_fixture_counting(&other_signer, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
    assert!(
        matches!(verdict, Err(PeerLineageFailure::Incomplete(_))),
        "got: {verdict:?}"
    );
    assert_eq!(fetched, vec![prior_addr]);
}

// ── A restarted chain (DSM Amendment A20) ─────────────────────────────────

/// The recipient's chain on its relationship with the sender, restarted: its
/// first step, certified by its AK, then a restart step continuing it at
/// `epoch`, both AKs signing the statement over the restart step's own
/// fields. `edit` changes the restart step after it is signed, given the
/// statement and the address of a second genuine first step of the
/// recipient. The countersign is certified by the restarted key, and the
/// bundle names the restart step as the recipient's predecessor; all three
/// steps are in the store.
fn restarted_chain(
    fx: &AcceptanceFixture,
    epoch: u64,
    edit: impl FnOnce(&mut generated::EkCertStepV1, &[u8; 32], [u8; 32]),
) -> AcceptanceFixture {
    use dsm::bilateral::cert_resync::RestartFields;
    let (recipient_ak_pk, recipient_ak_sk) = generate_sphincs_keypair().unwrap();
    let first_step = |h: [u8; 32]| {
        let (pk, _) = generate_sphincs_keypair().unwrap();
        generated::EkCertStepV1 {
            authority: Some(generated::ek_cert_step_v1::Authority::EkCert(
                sign_ek_cert(&recipient_ak_sk, &pk, &h).unwrap(),
            )),
            ek_pk: pk,
            h_n: h.to_vec(),
            prior_step_addr: None,
        }
        .encode_to_vec()
    };
    let (first, another) = (first_step([0x41; 32]), first_step([0x42; 32]));
    let (first_addr, another_first) = (ek_cert_step_addr(&first), ek_cert_step_addr(&another));

    let (restart_pk, restart_sk) = generate_sphincs_keypair().unwrap();
    let fields = RestartFields {
        relationship_key: dsm::core::bilateral_transaction_manager::compute_smt_key(
            &DEV_RECIP,
            &DEV_SENDER,
        ),
        predecessor: first_addr,
        agreed_tip: [0x43; 32],
        epoch,
        preserved_acceptance_commitment: [0x44; 32],
        new_key: &restart_pk,
    };
    let statement = fields.statement();
    let mut restart = fields.step(
        sphincs_sign(&recipient_ak_sk, &statement).unwrap(),
        sphincs_sign(&fx.sender_ak_sk, &statement).unwrap(),
    );
    edit(&mut restart, &statement, another_first);
    let restart_bytes = restart.encode_to_vec();
    let restart_addr = ek_cert_step_addr(&restart_bytes);

    let mut after = countersigned_after(fx, restart_addr, &restart_sk);
    after.recipient_ak_pk = recipient_ak_pk;
    after.steps.insert(first_addr, first);
    after.steps.insert(another_first, another);
    after.steps.insert(restart_addr, restart_bytes);
    after
}

fn restart_authority(step: &mut generated::EkCertStepV1) -> &mut generated::CertRestartV1 {
    match &mut step.authority {
        Some(generated::ek_cert_step_v1::Authority::Restart(r)) => r,
        _ => panic!("not a restart step"),
    }
}

/// A verifier outside the relationship walks the restarted chain: it fetches
/// the restart step and the step it continues, checks the predecessor as any
/// step, takes the restarted key on both AKs' signatures, and the acceptance
/// under that key verifies.
#[test]
fn a_restarted_chain_is_walked_through_its_restart_step() {
    let fx = acceptance_fixture();
    let restarted = restarted_chain(&fx, 1, |_, _, _| {});
    let (verdict, fetched) =
        verify_fixture_counting(&restarted, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
    verdict.expect("the acceptance under the restarted key verifies");
    assert_eq!(fetched.len(), 2, "the restart step and its predecessor");
}

/// Every way a restart step can fail to be the one both devices signed over
/// its own fields leaves an acceptance under it unverified: another
/// predecessor (a genuine step of the same chain), another agreed tip, epoch,
/// commitment or key, one device's signature alone, a signature by another
/// key, the two signatures swapped, and a restart naming no predecessor.
#[test]
fn a_restart_step_both_devices_did_not_sign_over_its_own_fields_does_not_chain() {
    let fx = acceptance_fixture();
    let another_key = generate_sphincs_keypair().unwrap().0;
    let another_sk = generate_sphincs_keypair().unwrap().1;
    type Edit = Box<dyn Fn(&mut generated::EkCertStepV1, &[u8; 32], [u8; 32])>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "another predecessor",
            Box::new(|s, _, another_first| s.prior_step_addr = Some(another_first.to_vec())),
        ),
        (
            "another agreed tip",
            Box::new(|s, _, _| s.h_n = vec![0x45; 32]),
        ),
        (
            "another epoch",
            Box::new(|s, _, _| restart_authority(s).epoch = 2),
        ),
        (
            "another commitment",
            Box::new(|s, _, _| {
                restart_authority(s).preserved_acceptance_commitment = vec![0x46; 32]
            }),
        ),
        (
            "another key",
            Box::new(move |s, _, _| s.ek_pk = another_key.clone()),
        ),
        (
            "the restarting device's signature alone",
            Box::new(|s, _, _| restart_authority(s).counterparty_sig = Vec::new()),
        ),
        (
            "the counterparty's signature by another key",
            Box::new(move |s, statement, _| {
                restart_authority(s).counterparty_sig =
                    sphincs_sign(&another_sk, statement).unwrap()
            }),
        ),
        (
            "the two signatures swapped",
            Box::new(|s, _, _| {
                let r = restart_authority(s);
                std::mem::swap(&mut r.restarting_sig, &mut r.counterparty_sig);
            }),
        ),
        (
            "no predecessor",
            Box::new(|s, _, _| s.prior_step_addr = None),
        ),
    ];
    for (label, edit) in cases {
        let restarted = restarted_chain(&fx, 1, |s, statement, another_first| {
            edit(s, statement, another_first)
        });
        let verdict = verify_fixture(&restarted, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
        assert!(
            matches!(&verdict, Err(PeerLineageFailure::Invalid(m)) if m.contains("EK restart step")),
            "{label}: {verdict:?}"
        );
    }
}

/// A chain restarted twice: the second restart continues the first and must
/// carry a greater epoch. The same epoch again does not chain; a greater one
/// does. A verifier that holds the second restart step checks the one
/// certificate after it and fetches nothing.
#[test]
fn a_second_restart_chains_only_past_the_first_epoch() {
    use dsm::bilateral::cert_resync::RestartFields;
    let fx = acceptance_fixture();
    let (recipient_ak_pk, recipient_ak_sk) = generate_sphincs_keypair().unwrap();
    let (first_pk, _) = generate_sphincs_keypair().unwrap();
    let first = generated::EkCertStepV1 {
        authority: Some(generated::ek_cert_step_v1::Authority::EkCert(
            sign_ek_cert(&recipient_ak_sk, &first_pk, &[0x41; 32]).unwrap(),
        )),
        ek_pk: first_pk,
        h_n: vec![0x41; 32],
        prior_step_addr: None,
    }
    .encode_to_vec();
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&DEV_RECIP, &DEV_SENDER);
    let restart = |predecessor: [u8; 32], epoch: u64, key: &[u8]| {
        let fields = RestartFields {
            relationship_key: rel,
            predecessor,
            agreed_tip: [0x43; 32],
            epoch,
            preserved_acceptance_commitment: [0x44; 32],
            new_key: key,
        };
        let statement = fields.statement();
        fields
            .step(
                sphincs_sign(&recipient_ak_sk, &statement).unwrap(),
                sphincs_sign(&fx.sender_ak_sk, &statement).unwrap(),
            )
            .encode_to_vec()
    };
    let (key_one, _) = generate_sphincs_keypair().unwrap();
    let (key_two, sk_two) = generate_sphincs_keypair().unwrap();
    let first_addr = ek_cert_step_addr(&first);
    let one = restart(first_addr, 3, &key_one);
    let one_addr = ek_cert_step_addr(&one);

    let chain = |second_epoch: u64| {
        let two = restart(one_addr, second_epoch, &key_two);
        let two_addr = ek_cert_step_addr(&two);
        let mut after = countersigned_after(&fx, two_addr, &sk_two);
        after.recipient_ak_pk = recipient_ak_pk.clone();
        after.steps.insert(first_addr, first.clone());
        after.steps.insert(one_addr, one.clone());
        after.steps.insert(two_addr, two);
        (after, two_addr)
    };

    let (same, _) = chain(3);
    let verdict = verify_fixture(&same, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
    assert!(
        matches!(&verdict, Err(PeerLineageFailure::Invalid(m)) if m.contains("does not exceed")),
        "{verdict:?}"
    );
    let (later, two_addr) = chain(4);
    let (verdict, fetched) =
        verify_fixture_counting(&later, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
    verdict.expect("a restart past the first epoch chains");
    assert_eq!(fetched.len(), 3);

    let mut holding = acceptance_clone(&later);
    holding.held.insert((DEV_RECIP, two_addr), key_two.clone());
    let (verdict, fetched) =
        verify_fixture_counting(&holding, DEV_RECIP, &fx.transfer_bytes, &fx.child_tip);
    verdict.expect("from the held restart step");
    assert!(fetched.is_empty(), "fetched {} EK steps", fetched.len());
}

// ── The exact peer-debit predicate's refusal clauses ───────────────────────
