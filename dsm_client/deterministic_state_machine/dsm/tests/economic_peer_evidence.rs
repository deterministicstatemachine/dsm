// SPDX-License-Identifier: Apache-2.0

//! The PR2 evidence formats, adversarially: successor evidence (`sigma_dsm`),
//! the portable acceptance bundle (`sig_b` IS the acceptance), the
//! signer-identity EK ancestry, and the exact peer-debit predicate's refusal
//! clauses.

#![allow(clippy::disallowed_methods)]

use prost::Message;

use dsm::crypto::ephemeral_key::sign_ek_cert;
use dsm::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
use dsm::economic::credit::{CreditSource, CreditSourceValidatedPeerDebit};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::peer_acceptance::{
    acceptance_evidence_addr, ek_cert_step_addr, verify_peer_transfer_acceptance, AcceptanceParty,
};
use dsm::economic::provenance::{
    verify_credit_source, FaucetTicketWin, PeerLineageFailure, ProvenanceContext, ProvenanceError,
    ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::successor_evidence::{
    sign_dsm_successor_evidence, verify_dsm_successor_evidence, SuccessorEvidenceError,
};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::proto as generated;
use dsm::types::receipt_types::{
    compute_receipt_b_canonical_target, compute_receipt_challenge_response_target,
    StitchedReceiptV2,
};
use dsm::types::token_types::Balance;

const G_SENDER: [u8; 32] = [0x51; 32];
const DEV_SENDER: [u8; 32] = [0x52; 32];
const G_RECIP: [u8; 32] = [0x61; 32];
const DEV_RECIP: [u8; 32] = [0x62; 32];

fn era() -> [u8; 32] {
    dsm::core::token::token_state_manager::era_policy_commit()
}

fn transfer_to(recipient: [u8; 32], amount: u64) -> Operation {
    Operation::Transfer {
        to_device_id: recipient.to_vec(),
        amount: Balance::from_state(amount, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: era(),
        mode: TransactionMode::Bilateral,
        nonce: vec![9; 32],
        verification: VerificationType::Standard,
        pre_commit: None,
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

/// A resolver hand-crafted to return one VPT; evidence store empty.
struct OnePeer {
    vpt: ValidatedPeerTransition,
}
impl ProvenanceResolver for OnePeer {
    fn validated_peer_transition(
        &self,
        _g: &[u8; 32],
        _d: &[u8; 32],
        _p: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Ok(self.vpt.clone())
    }
    fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
        None
    }

    fn winning_settlement_slot_claim(
        &self,
        _vault_id: &[u8; 32],
        _parent_sequence: u64,
    ) -> Option<dsm::economic::provenance::SettlementSlotWin> {
        None
    }
    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        _addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete("no evidence store".into()))
    }

    fn anchored_policy_bytes(
        &self,
        _policy_commit: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "this fixture roots no token anchors".into(),
        ))
    }
}

/// A peer VPT whose witness has one exact debit, with `verified_operation`
/// supplied by the test.
fn peer_vpt(verified_operation: Operation, debit_amount: u64) -> ValidatedPeerTransition {
    let mut tree = EconomicSmt::new();
    let pre = EconomicLeafState::Balance(EconomicBalanceState::new(era(), 100).unwrap());
    let key = pre.leaf_key(&G_SENDER, &DEV_SENDER);
    tree.insert(key, pre.leaf_value().unwrap());
    let pre_root = tree.root();
    let post =
        EconomicLeafState::Balance(EconomicBalanceState::new(era(), 100 - debit_amount).unwrap());
    let siblings = tree.siblings(&key).to_vec();
    let mutation = EconomicLeafMutation::new(Some(pre), Some(post.clone()), siblings).unwrap();
    tree.insert(key, post.leaf_value().unwrap());
    let witness = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        [0x0E; 32],
        dsm::economic::faucet::dsm_operation_digest(&verified_operation.to_bytes()),
        vec![mutation],
        Vec::new(),
    )
    .unwrap();
    ValidatedPeerTransition {
        peer_genesis: G_SENDER,
        peer_devid: DEV_SENDER,
        validated_root:
            dsm::economic::lineage::ValidatedEconomicRoot::rehydrate_from_admitted_store(
                4,
                tree.root(),
            ),
        witness,
        proven_ak: vec![0xAA; 64],
        c_dsm_plus: [0xC5; 32],
        verified_operation,
    }
}

/// The consuming recipient's witness: one credit funded by the peer debit.
fn consuming_witness(amount: u64) -> EconomicTransitionWitness {
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = EconomicLeafState::Balance(EconomicBalanceState::new(era(), amount).unwrap());
    let key = credit.leaf_key(&G_RECIP, &DEV_RECIP);
    let siblings = tree.siblings(&key).to_vec();
    let mutation = EconomicLeafMutation::new(None, Some(credit.clone()), siblings).unwrap();
    tree.insert(key, credit.leaf_value().unwrap());
    EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        [0x0F; 32],
        [0x77; 32],
        vec![mutation],
        vec![CreditSource::ValidatedPeerDebit(
            CreditSourceValidatedPeerDebit {
                credit_mutation_index: 0,
                peer_genesis: G_SENDER,
                peer_devid: DEV_SENDER,
                peer_economic_position: 4,
                peer_debit_mutation_index: 0,
                acceptance_evidence_addr: [0x44; 32],
            },
        )],
    )
    .unwrap()
}

fn recip_ctx<'a>(ak: &'a [u8], set_id: &'a [u8; 32]) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G_RECIP,
        device_id: &DEV_RECIP,
        economic_position: 1,
        network_id: b"dsm-testnet",
        proven_ak: ak,
        canonical_storage_set_id: *set_id,
        // The consuming substrate's own pair; these fixtures refuse before
        // the pair is compared, so a placeholder pair is inert here.
        substrate_b_pair: Some(([0x7A; 32], [0x7B; 32])),
        verified_operation: None,
    }
}

#[test]
fn a_peer_burn_cannot_fund_a_credit() {
    // The correction-2 control: "some peer had a validated debit" is not the
    // semantics — a Burn debit funds nothing.
    let burn = Operation::Burn {
        amount: Balance::from_state(40, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: era(),
        proof_of_ownership: Vec::new(),
        message: String::new(),
    };
    let resolver = OnePeer {
        vpt: peer_vpt(burn, 40),
    };
    let w = consuming_witness(40);
    let set_id = [0xB1; 32];
    assert_eq!(
        verify_credit_source(
            &w.credit_sources[0],
            &w,
            &resolver,
            &recip_ctx(&[0xAB; 64], &set_id)
        )
        .unwrap_err(),
        ProvenanceError::PeerDebitIsNotAnOnlineTransfer
    );
}

#[test]
fn a_transfer_to_a_third_identity_cannot_fund_this_credit() {
    let resolver = OnePeer {
        vpt: peer_vpt(transfer_to([0x99; 32], 40), 40),
    };
    let w = consuming_witness(40);
    let set_id = [0xB1; 32];
    assert_eq!(
        verify_credit_source(
            &w.credit_sources[0],
            &w,
            &resolver,
            &recip_ctx(&[0xAB; 64], &set_id)
        )
        .unwrap_err(),
        ProvenanceError::PeerDebitNotAddressedToConsumer
    );
}

#[test]
fn a_debit_that_is_not_the_operations_debit_is_refused() {
    // Operation says 40; the named mutation debits 30 — the descriptor is
    // pointing at a debit the operation did not perform.
    let resolver = OnePeer {
        vpt: peer_vpt(transfer_to(DEV_RECIP, 40), 30),
    };
    let w = consuming_witness(30);
    let set_id = [0xB1; 32];
    assert_eq!(
        verify_credit_source(
            &w.credit_sources[0],
            &w,
            &resolver,
            &recip_ctx(&[0xAB; 64], &set_id)
        )
        .unwrap_err(),
        ProvenanceError::PeerDebitIndexIsNotTheOperationDebit
    );
}

#[test]
fn an_unresolvable_acceptance_fails_closed_as_incomplete() {
    // Everything about the debit is right; the acceptance bytes cannot be
    // fetched. The taxonomy survives: Incomplete, not Invalid.
    let resolver = OnePeer {
        vpt: peer_vpt(transfer_to(DEV_RECIP, 40), 40),
    };
    let w = consuming_witness(40);
    let set_id = [0xB1; 32];
    match verify_credit_source(
        &w.credit_sources[0],
        &w,
        &resolver,
        &recip_ctx(&[0xAB; 64], &set_id),
    )
    .unwrap_err()
    {
        ProvenanceError::AcceptanceEvidence(PeerLineageFailure::Incomplete(_)) => {}
        other => panic!("expected Incomplete acceptance fetch, got {other:?}"),
    }
}

#[test]
fn the_addr_checked_acceptance_bytes_must_hash_to_the_descriptor_address() {
    // The resolver returns bytes that do NOT hash to the descriptor's
    // acceptance_evidence_addr: refused as Invalid before any verification.
    struct WrongBytes {
        vpt: ValidatedPeerTransition,
    }
    impl ProvenanceResolver for WrongBytes {
        fn validated_peer_transition(
            &self,
            _g: &[u8; 32],
            _d: &[u8; 32],
            _p: u64,
        ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
            Ok(self.vpt.clone())
        }
        fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
            None
        }

        fn winning_settlement_slot_claim(
            &self,
            _vault_id: &[u8; 32],
            _parent_sequence: u64,
        ) -> Option<dsm::economic::provenance::SettlementSlotWin> {
            None
        }
        fn immutable_evidence(
            &self,
            _n: dsm::crypto::domain::TaggedHashDomain<'static>,
            _a: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Ok(vec![0xEE; 64])
        }

        fn anchored_policy_bytes(
            &self,
            _policy_commit: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(
                "this fixture roots no token anchors".into(),
            ))
        }
    }
    let resolver = WrongBytes {
        vpt: peer_vpt(transfer_to(DEV_RECIP, 40), 40),
    };
    let w = consuming_witness(40);
    let set_id = [0xB1; 32];
    match verify_credit_source(
        &w.credit_sources[0],
        &w,
        &resolver,
        &recip_ctx(&[0xAB; 64], &set_id),
    )
    .unwrap_err()
    {
        ProvenanceError::AcceptanceEvidence(PeerLineageFailure::Invalid(m)) => {
            assert!(m.contains("hash to the descriptor"), "{m}");
        }
        other => panic!("expected Invalid addr mismatch, got {other:?}"),
    }
    let _ = acceptance_evidence_addr(b"anchor the helper in this file");
}
