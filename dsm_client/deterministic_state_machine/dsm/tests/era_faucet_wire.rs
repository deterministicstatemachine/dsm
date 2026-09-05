// SPDX-License-Identifier: Apache-2.0

//! The ERA faucet wire: canonical identity, ticket claims, the accepting
//! gate, and the authoritative provenance arm.
//!
//! The controls that matter are the ones an attacker would aim at: the
//! canonical-id rule (an invented faucet id must not be a fresh 80B
//! universe), the fence coupling (a claim must not be a raw local mint), and
//! the position+digest binding (one ticket funds at most one transition).

#![allow(clippy::disallowed_methods)]

use dsm::economic::classifier::{classify, EconomicEffect};
use dsm::economic::credit::{CreditSource, CreditSourceValidatedFaucetDistribution};
use dsm::economic::faucet::{
    decode_and_verify_faucet_ticket_claim, dsm_operation_digest, era_faucet_id,
    faucet_claim_evidence_addr, faucet_ticket_source_id, sign_faucet_ticket_claim,
    FaucetClaimError, FaucetTicketClaimBody, ERA_FAUCET_PAYOUT, ERA_FAUCET_TICKET_COUNT,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{
    verify_credit_source, FaucetTicketWin, ProvenanceContext, ProvenanceError, PeerLineageFailure,
    ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::types::operations::Operation;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];
const NETWORK: &[u8] = b"dsm-testnet";
const SET_ID: [u8; 32] = [0xB1; 32];

fn era_commit() -> [u8; 32] {
    dsm::core::token::token_state_manager::builtin_policy_commit_for_token("ERA").expect("builtin")
}

fn keypair() -> (Vec<u8>, Vec<u8>) {
    dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
}

fn claim_op(faucet_id: [u8; 32], ticket_index: u64) -> Operation {
    Operation::FaucetClaim {
        faucet_id,
        ticket_index,
    }
}

/// A signed, quorum-winning claim plus the witness of the transition it
/// funds, built the way an honest claimant builds them.
struct Fixture {
    envelope: Vec<u8>,
    witness: EconomicTransitionWitness,
    descriptor: CreditSourceValidatedFaucetDistribution,
    pk: Vec<u8>,
}

fn fixture(position: u64) -> Fixture {
    let (pk, sk) = keypair();
    let faucet_id = era_faucet_id(NETWORK);
    let ticket_index = 42u64;

    let op = claim_op(faucet_id, ticket_index);
    let op_digest = dsm_operation_digest(&op.to_bytes());

    let body = FaucetTicketClaimBody {
        faucet_id,
        ticket_index,
        claimant_genesis: G,
        claimant_devid: DEV,
        claimant_economic_position: position,
        recipient_operation_digest: op_digest,
        claimant_public_key: pk.clone(),
        storage_set_id: SET_ID,
    };
    let envelope = sign_faucet_ticket_claim(&body, &sk).expect("signable");

    // The credited transition: empty tree -> +100 ERA.
    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = EconomicLeafState::Balance(
        EconomicBalanceState::new(era_commit(), ERA_FAUCET_PAYOUT).expect("nonzero"),
    );
    let key = credit.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let mutation =
        EconomicLeafMutation::new(None, Some(credit.clone()), siblings).expect("well-formed");
    tree.insert(key, credit.leaf_value().expect("encodable"));
    let post_root = tree.root();

    let descriptor = CreditSourceValidatedFaucetDistribution {
        credit_mutation_index: 0,
        faucet_id,
        ticket_index,
        faucet_claim_evidence_addr: faucet_claim_evidence_addr(&envelope),
    };
    let witness = EconomicTransitionWitness::new(
        pre_root,
        post_root,
        [0x0E; 32],
        op_digest,
        vec![mutation],
        vec![CreditSource::ValidatedFaucetDistribution(
            descriptor.clone(),
        )],
    )
    .expect("valid witness");

    Fixture {
        envelope,
        witness,
        descriptor,
        pk,
    }
}

/// A resolver holding exactly one quorum-winning envelope.
struct OneTicket {
    faucet_id: [u8; 32],
    ticket_index: u64,
    envelope: Vec<u8>,
}
impl ProvenanceResolver for OneTicket {
    fn validated_peer_transition(
        &self,
        _g: &[u8; 32],
        _d: &[u8; 32],
        _p: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "no peer store in this fixture".into(),
        ))
    }
    fn winning_faucet_ticket(&self, f: &[u8; 32], i: u64) -> Option<FaucetTicketWin> {
        (*f == self.faucet_id && i == self.ticket_index).then(|| FaucetTicketWin {
            envelope_bytes: self.envelope.clone(),
        })
    }

    fn winning_settlement_slot_claim(
        &self,
        _vault_id: &[u8; 32],
        _parent_sequence: u64,
        _storage_set: &dsm::ccb::StorageSetMembers,
        _quorum: u32,
    ) -> Option<dsm::economic::provenance::SettlementSlotWin> {
        None
    }

    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        _addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "no evidence store in this fixture".into(),
        ))
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

fn ctx<'a>(position: u64, ak: &'a [u8]) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G,
        device_id: &DEV,
        economic_position: position,
        network_id: NETWORK,
        proven_ak: ak,
        canonical_storage_set_id: SET_ID,
        substrate_b_pair: None,
        verified_operation: None,
    }
}

// ── Identity and envelope ──────────────────────────────────────────────────

#[test]
fn the_envelope_round_trips_and_is_strict() {
    let fx = fixture(1);
    let v = decode_and_verify_faucet_ticket_claim(&fx.envelope).expect("verifies");
    assert_eq!(v.envelope_bytes, fx.envelope);

    // Decodable-but-non-canonical: unknown field, silently skipped by prost,
    // caught only by the re-encode comparison.
    let mut padded = fx.envelope.clone();
    padded.extend_from_slice(&[0x18, 0x01]);
    assert!(matches!(
        decode_and_verify_faucet_ticket_claim(&padded),
        Err(FaucetClaimError::Malformed("envelope is not canonical"))
    ));

    let mut tampered = fx.envelope.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(decode_and_verify_faucet_ticket_claim(&tampered).is_err());
}

// ── The authoritative provenance arm ───────────────────────────────────────

#[test]
fn a_winning_ticket_funds_exactly_the_payout() {
    let fx = fixture(1);
    let resolver = OneTicket {
        faucet_id: fx.descriptor.faucet_id,
        ticket_index: fx.descriptor.ticket_index,
        envelope: fx.envelope.clone(),
    };
    let funded = verify_credit_source(
        &fx.witness.credit_sources[0],
        &fx.witness,
        &resolver,
        &ctx(1, &fx.pk),
    )
    .expect("a quorum-won canonical ticket funds the credit");
    assert_eq!(funded.amount, ERA_FAUCET_PAYOUT);
    assert_eq!(funded.policy_commit, era_commit());
    assert_eq!(
        funded.source_id,
        faucet_ticket_source_id(&fx.descriptor.faucet_id, fx.descriptor.ticket_index)
    );
}

#[test]
fn wrong_faucet_id_cannot_create_a_second_ticket_universe() {
    // THE stop-the-line control. Everything about this claim is internally
    // consistent — envelope signed, winner matches descriptor, evidence addr
    // matches — except the faucet id is an INVENTED one. If only
    // descriptor==winner were checked, each invented id would be a fresh
    // 800M-ticket universe and the 80B cap would be fiction.
    let (pk, sk) = keypair();
    let invented = [0xF4; 32];
    let op = claim_op(invented, 7);
    let op_digest = dsm_operation_digest(&op.to_bytes());
    let body = FaucetTicketClaimBody {
        faucet_id: invented,
        ticket_index: 7,
        claimant_genesis: G,
        claimant_devid: DEV,
        claimant_economic_position: 1,
        recipient_operation_digest: op_digest,
        claimant_public_key: pk.clone(),
        storage_set_id: SET_ID,
    };
    let envelope = sign_faucet_ticket_claim(&body, &sk).expect("signable");

    let mut tree = EconomicSmt::new();
    let pre_root = tree.root();
    let credit = EconomicLeafState::Balance(
        EconomicBalanceState::new(era_commit(), ERA_FAUCET_PAYOUT).expect("nonzero"),
    );
    let key = credit.leaf_key(&G, &DEV);
    let siblings = tree.siblings(&key).to_vec();
    let mutation = EconomicLeafMutation::new(None, Some(credit.clone()), siblings).unwrap();
    tree.insert(key, credit.leaf_value().unwrap());
    let descriptor = CreditSourceValidatedFaucetDistribution {
        credit_mutation_index: 0,
        faucet_id: invented,
        ticket_index: 7,
        faucet_claim_evidence_addr: faucet_claim_evidence_addr(&envelope),
    };
    let witness = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        [0x0E; 32],
        op_digest,
        vec![mutation],
        vec![CreditSource::ValidatedFaucetDistribution(descriptor)],
    )
    .unwrap();
    let resolver = OneTicket {
        faucet_id: invented,
        ticket_index: 7,
        envelope,
    };
    assert!(matches!(
        verify_credit_source(
            &witness.credit_sources[0],
            &witness,
            &resolver,
            &ctx(1, &pk)
        ),
        Err(ProvenanceError::NotTheCanonicalFaucet { .. })
    ));
}

#[test]
fn the_ak_binding_is_checked_not_assumed() {
    // Signature-valid under ITS OWN key — but that key is not the P0–P6-proven
    // AK. Storage-node bearer attribution is not this binding.
    let fx = fixture(1);
    let resolver = OneTicket {
        faucet_id: fx.descriptor.faucet_id,
        ticket_index: fx.descriptor.ticket_index,
        envelope: fx.envelope.clone(),
    };
    let other_ak = keypair().0;
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(1, &other_ak),
        ),
        Err(ProvenanceError::FaucetClaimantMismatch)
    ));
}

#[test]
fn one_ticket_funds_at_most_one_position() {
    // NON-REUSE. The envelope commits target position 1; presenting the same
    // winning ticket for the transition at position 2 must fail — position
    // binding is what makes the no-nonce operation sound, since two minimal
    // claims' bytes can be identical.
    let fx = fixture(1);
    let resolver = OneTicket {
        faucet_id: fx.descriptor.faucet_id,
        ticket_index: fx.descriptor.ticket_index,
        envelope: fx.envelope.clone(),
    };
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &resolver,
            &ctx(2, &fx.pk),
        ),
        Err(ProvenanceError::FaucetBindingMismatch)
    ));
}

#[test]
fn a_foreign_register_set_is_refused() {
    let fx = fixture(1);
    let resolver = OneTicket {
        faucet_id: fx.descriptor.faucet_id,
        ticket_index: fx.descriptor.ticket_index,
        envelope: fx.envelope.clone(),
    };
    let mut c = ctx(1, &fx.pk);
    c.canonical_storage_set_id = [0x77; 32]; // canonical set differs from the claim's
    assert!(matches!(
        verify_credit_source(&fx.witness.credit_sources[0], &fx.witness, &resolver, &c),
        Err(ProvenanceError::FaucetForeignSet)
    ));
}

#[test]
fn no_quorum_winner_fails_closed_and_out_of_range_is_refused() {
    let fx = fixture(1);
    struct Nothing;
    impl ProvenanceResolver for Nothing {
        fn validated_peer_transition(
            &self,
            _g: &[u8; 32],
            _d: &[u8; 32],
            _p: u64,
        ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(
                "no peer store in this fixture".into(),
            ))
        }
        fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
            None
        }

        fn winning_settlement_slot_claim(
            &self,
            _vault_id: &[u8; 32],
            _parent_sequence: u64,
            _storage_set: &dsm::ccb::StorageSetMembers,
            _quorum: u32,
        ) -> Option<dsm::economic::provenance::SettlementSlotWin> {
            None
        }

        fn immutable_evidence(
            &self,
            _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
            _addr: &[u8; 32],
        ) -> Result<Vec<u8>, PeerLineageFailure> {
            Err(PeerLineageFailure::Incomplete(
                "no evidence store in this fixture".into(),
            ))
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
    assert!(matches!(
        verify_credit_source(
            &fx.witness.credit_sources[0],
            &fx.witness,
            &Nothing,
            &ctx(1, &fx.pk)
        ),
        Err(ProvenanceError::FaucetTicketNotEstablished { .. })
    ));

    // Out-of-range coordinate: not a ticket that exists.
    let mut d = fx.descriptor.clone();
    d.ticket_index = ERA_FAUCET_TICKET_COUNT;
    let src = CreditSource::ValidatedFaucetDistribution(d);
    assert!(matches!(
        verify_credit_source(&src, &fx.witness, &Nothing, &ctx(1, &fx.pk)),
        Err(ProvenanceError::TicketIndexOutOfRange { .. })
    ));
}

// ── The accepting gate: not a raw local mint ───────────────────────────────

#[test]
fn faucet_claim_cannot_install_balance_without_the_admission_fence() {
    use dsm::economic::admission::{PendingAdmissionKind, PendingEconomicAdmission};
    use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};

    let devid = [0x33u8; 32];
    let head = DeviceState::new([0x44u8; 32], devid, vec![0xAA; 32], 64);
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid, &devid);
    let tip =
        dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(&devid, &devid);
    let op = claim_op(era_faucet_id(NETWORK), 42);
    let delta = BalanceDelta {
        policy_commit: era_commit(),
        direction: BalanceDirection::Credit,
        amount: ERA_FAUCET_PAYOUT,
    };

    // 1. No pending admission: REFUSED. This is the raw-local-mint control —
    //    an adversarial client calling advance directly gets a core refusal.
    let err = head
        .advance(
            rel,
            devid,
            op.clone(),
            vec![0x11; 32],
            None,
            std::slice::from_ref(&delta),
            Some(tip),
            None,
            None,
            None,
        )
        .expect_err("a claim with no pending admission must not install balance");
    assert!(
        err.to_string().contains("no pending economic admission"),
        "refusal must come from the fence coupling: {err}"
    );

    // 2. Pending admission bound to THIS operation's digest (attached in
    //    Prepared, which does not fence): the SAME advance succeeds.
    let op_digest = dsm_operation_digest(&op.to_bytes());
    let pending =
        PendingEconomicAdmission::prepared(PendingAdmissionKind::DsmBacked, 1, [1; 32], op_digest);
    let fenced = head.with_pending_economic_admission(Some(pending.clone()));
    let outcome = fenced
        .advance(
            rel,
            devid,
            op.clone(),
            vec![0x11; 32],
            None,
            std::slice::from_ref(&delta),
            Some(tip),
            None,
            None,
            None,
        )
        .expect("the admitted operation advances");
    assert_eq!(
        outcome.new_device_state.balance(&era_commit()),
        ERA_FAUCET_PAYOUT
    );

    // 3. A pending admission for a DIFFERENT operation: refused.
    let other = claim_op(era_faucet_id(NETWORK), 43);
    let err = fenced
        .advance(
            rel,
            devid,
            other,
            vec![0x11; 32],
            None,
            std::slice::from_ref(&delta),
            Some(tip),
            None,
            None,
            None,
        )
        .expect_err("the admission authorizes exactly one operation");
    assert!(err.to_string().contains("does not match the pending"));

    // 4. Out-of-range ticket: refused before anything else.
    let oob = claim_op(era_faucet_id(NETWORK), ERA_FAUCET_TICKET_COUNT);
    assert!(head
        .advance(
            rel,
            devid,
            oob,
            vec![0x11; 32],
            None,
            &[delta],
            Some(tip),
            None,
            None,
            None
        )
        .is_err());
}

#[test]
fn conservation_refuses_anything_but_the_derived_payout() {
    use dsm::types::device_state::{BalanceDelta, BalanceDirection, DeviceState};
    let devid = [0x33u8; 32];
    let head = DeviceState::new([0x44u8; 32], devid, vec![0xAA; 32], 64);
    let rel = dsm::core::bilateral_transaction_manager::compute_smt_key(&devid, &devid);
    let tip =
        dsm::core::bilateral_transaction_manager::initial_chain_tip_from_device_ids(&devid, &devid);
    let op = claim_op(era_faucet_id(NETWORK), 42);

    // Wrong amount and wrong asset each refused: nothing is caller-chosen.
    for delta in [
        BalanceDelta {
            policy_commit: era_commit(),
            direction: BalanceDirection::Credit,
            amount: 500,
        },
        BalanceDelta {
            policy_commit: [0xBB; 32],
            direction: BalanceDirection::Credit,
            amount: ERA_FAUCET_PAYOUT,
        },
        BalanceDelta {
            policy_commit: era_commit(),
            direction: BalanceDirection::Debit,
            amount: ERA_FAUCET_PAYOUT,
        },
    ] {
        let err = head
            .advance(
                rel,
                devid,
                op.clone(),
                vec![0x11; 32],
                None,
                std::slice::from_ref(&delta),
                Some(tip),
                None,
                None,
                None,
            )
            .expect_err("conservation must refuse");
        assert!(
            err.to_string().contains("conservation"),
            "must fail in conservation, got: {err}"
        );
    }
}

// ── Classifier and drift ───────────────────────────────────────────────────

#[test]
fn a_faucet_claim_is_a_closed_write_set() {
    assert_eq!(
        classify(&claim_op(era_faucet_id(NETWORK), 0)),
        EconomicEffect::ClosedWriteSet
    );
}

#[test]
fn the_ticket_model_has_no_shared_state_idioms() {
    // The drift tripwire, as a test: the rejected global-head design creeps
    // back through these identifiers. `reserve` appears only inside the word
    // "reserved"-style prose, so match the exact idioms.
    // Comment lines are skipped: prose NAMING a forbidden idiom (the module
    // header documents why these are forbidden) must not trip its own gate —
    // the same rule the toolchain-consistency script applies.
    let code: String = include_str!("../src/economic/faucet.rs")
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["faucet_sequence", "remaining", "parent_state_commitment"] {
        assert!(
            !code.contains(forbidden),
            "economic/faucet.rs CODE contains the shared-state idiom {forbidden:?} — the \
             global-head design is creeping back"
        );
    }
}
