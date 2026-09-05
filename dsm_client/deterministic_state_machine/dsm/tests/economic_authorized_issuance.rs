// SPDX-License-Identifier: MIT OR Apache-2.0

//! Class `0x0029` — policy-authorized issuance, end to end through the
//! `0x0023` arm.
//!
//! The fixture is real: a real 2-of-3 SPHINCS+ signer set, real policy bytes
//! whose content hash IS the `policy_commit` the operation names, a real CCB
//! authorization body, real signatures over its signing digest, and a write
//! set built by the REAL builder. Nothing here is hand-assembled to agree with
//! itself.
//!
//! What these prove is narrow and deliberate: **these exact units were issued
//! by the authority the committed token policy permits.** They do not prove,
//! and must never be read as proving, that the units are redeemable for or
//! collateralized by anything.

// Test-only: `.expect` is the honest failure mode for a fixture whose whole
// purpose is that its inputs are valid. The same allowance the sibling
// provenance suites carry.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;

use dsm::crypto::sphincs::{generate_keypair, sphincs_sign, SphincsVariant};
use dsm::economic::issuance::IssuanceAuthorizationBody;
use dsm::economic::provenance::{
    verify_transition_provenance, FaucetTicketWin, PeerLineageFailure, ProvenanceContext,
    ProvenanceError, ProvenanceResolver, ValidatedPeerTransition,
};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{build_write_set, CreditSourceFacts, EconomicPreState};
use dsm::types::operations::Operation;
use dsm::types::proto as generated;
use dsm::types::token_types::Balance;
use prost::Message;

const G: [u8; 32] = [0x91; 32];
const DEV: [u8; 32] = [0x92; 32];
const POSITION: u64 = 5;

/// Build `TokenPolicyV3` bytes in the committed blob layout.
///
/// This mirrors the SDK's producer exactly; the point of writing it here is
/// that the VERIFIER must reach the same decision from bytes alone, so the
/// test builds bytes rather than calling the SDK.
#[allow(clippy::too_many_arguments)]
fn policy_bytes(
    signers: &[Vec<u8>],
    threshold: u8,
    mint_burn: bool,
    transferable: bool,
    unlimited: bool,
    allowlist: &[[u8; 32]],
) -> Vec<u8> {
    let mut flags = 0u8;
    if mint_burn {
        flags |= 0x01;
    }
    if transferable {
        flags |= 0x02;
    }
    if !allowlist.is_empty() {
        flags |= 0x04;
    }
    if unlimited {
        flags |= 0x08;
    }
    let mut b = vec![3u8, 0u8, flags, threshold, signers.len() as u8];
    for pk in signers {
        b.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        b.extend_from_slice(pk);
    }
    let ticker = b"NEW";
    b.push(ticker.len() as u8);
    b.extend_from_slice(ticker);
    let alias = b"New Coin";
    b.extend_from_slice(&(alias.len() as u16).to_be_bytes());
    b.extend_from_slice(alias);
    b.push(0); // decimals
    b.extend_from_slice(&0u128.to_be_bytes()); // max_supply
    b.extend_from_slice(&0u128.to_be_bytes()); // initial_alloc
    b.extend_from_slice(&0u16.to_be_bytes()); // description
    b.extend_from_slice(&0u16.to_be_bytes()); // icon_url
    if allowlist.is_empty() {
        // Kind NONE still carries its u16 count, committed as zero — the
        // canonical SDK packer always writes it, and this helper's whole
        // reason to exist is producing the bytes the packer actually commits.
        b.push(0);
        b.extend_from_slice(&0u16.to_be_bytes());
    } else {
        b.push(1);
        b.extend_from_slice(&(allowlist.len() as u16).to_be_bytes());
        for d in allowlist {
            b.extend_from_slice(d);
        }
    }
    generated::TokenPolicyV3 { policy_bytes: b }.encode_to_vec()
}

fn policy_commit_of(proto: &[u8]) -> [u8; 32] {
    dsm::crypto::blake3::domain_hash_bytes(dsm::common::domain_tags::TAG_DSM_POLICY, proto)
}

struct Fixture {
    op: Operation,
    witness: EconomicTransitionWitness,
    evidence_addr: [u8; 32],
    evidence_bytes: Vec<u8>,
    policy_commit: [u8; 32],
}

struct IssuanceResolver {
    evidence_addr: [u8; 32],
    evidence_bytes: Vec<u8>,
}

impl ProvenanceResolver for IssuanceResolver {
    fn root_register_candidate_set(
        &self,
        _network_id: &[u8],
    ) -> Result<dsm::ccb::StorageSetMembers, dsm::economic::provenance::PeerLineageFailure> {
        Ok(crate::beta_candidate_set())
    }

    fn validated_peer_transition(
        &self,
        _g: &[u8; 32],
        _d: &[u8; 32],
        _p: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        Err(PeerLineageFailure::Incomplete(
            "no peer lineage here".into(),
        ))
    }
    fn winning_faucet_ticket(&self, _f: &[u8; 32], _t: u64) -> Option<FaucetTicketWin> {
        None
    }
    fn settlement_slot_observation(
        &self,
        _v: &[u8; 32],
        _p: u64,
        _s: &dsm::ccb::StorageSetMembers,
        _q: u32,
    ) -> dsm::economic::cell_observation::CellObservation {
        // This fixture roots no settlement slots: it cannot observe the
        // cell, which is not the same as observing it empty.
        dsm::economic::cell_observation::CellObservation::Unavailable {
            attributed: 0,
            required: 2,
        }
    }
    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        if *addr == self.evidence_addr {
            Ok(self.evidence_bytes.clone())
        } else {
            Err(PeerLineageFailure::Incomplete("unknown address".into()))
        }
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

/// One honest issuance: 2-of-3 over 1_000 units of an uncapped policy.
fn fixture(
    signer_count: usize,
    signing: usize,
    amount: u64,
    unlimited: bool,
    mint_burn: bool,
    allowlist: &[[u8; 32]],
    name_authority: bool,
) -> Fixture {
    let keys: Vec<_> = (0..signer_count)
        .map(|_| generate_keypair(SphincsVariant::SPX256f).expect("keypair"))
        .collect();
    let pks: Vec<Vec<u8>> = keys.iter().map(|k| k.public_key.clone()).collect();
    // The signing keys and the keys the POLICY names are separable on purpose:
    // a bundle can carry perfectly valid signatures under a policy that names
    // nobody, which is the only way to reach the no-authority conjunct instead
    // of stopping at the decoder's empty-signature check.
    let policy_pks: Vec<Vec<u8>> = if name_authority {
        pks.clone()
    } else {
        Vec::new()
    };
    let proto = policy_bytes(&policy_pks, 2, mint_burn, true, unlimited, allowlist);
    let policy_commit = policy_commit_of(&proto);

    // The operation is FROZEN FIRST, so its digest exists before anything is
    // signed. This ordering is the whole reason the signatures live in the
    // evidence bundle rather than in `proof_of_authorization`.
    let op = Operation::Mint {
        amount: Balance::from_state(amount, [0u8; 32]),
        token_id: b"NEW".to_vec(),
        policy_commit,
        message: String::new(),
    };
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&op.to_bytes());

    let body = IssuanceAuthorizationBody {
        policy_commit,
        issuer_genesis: G,
        issuer_devid: DEV,
        issuer_economic_position: POSITION,
        recipient_operation_digest: op_digest,
        amount,
    };
    let body_ccb = body.encode().expect("body ccb");
    let digest = body.signing_digest().expect("signing digest");
    let signatures: Vec<generated::PolicySignerSignatureV1> = keys
        .iter()
        .take(signing)
        .map(|k| generated::PolicySignerSignatureV1 {
            signer_public_key: k.public_key.clone(),
            signature: sphincs_sign(&k.secret_key, &digest).expect("sign"),
        })
        .collect();
    let evidence_bytes = generated::IssuanceAuthorizationEvidenceV1 {
        canonical_policy_bytes: proto,
        authorization_body_ccb: body_ccb,
        signatures,
    }
    .encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ISSUANCE_AUTHORIZATION_EVIDENCE,
        &evidence_bytes,
    );

    let mut tree = EconomicSmt::new();
    let balances = BTreeMap::new();
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &[0x42u8; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::AuthorizedIssuance {
            issuance_authorization_addr: evidence_addr,
        },
    )
    .expect("the REAL builder builds the issuance write set");
    let witness = EconomicTransitionWitness::new(
        [0u8; 32],
        built.post_root,
        [0x42u8; 32],
        op_digest,
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");

    Fixture {
        op,
        witness,
        evidence_addr,
        evidence_bytes,
        policy_commit,
    }
}

/// Like [`fixture`], but the SECOND signature comes from a keypair the policy
/// does not name. The bundle is assembled with it, so the evidence address the
/// descriptor carries is the address of these exact bytes.
fn fixture_with_stranger(signer_count: usize, amount: u64) -> Fixture {
    let keys: Vec<_> = (0..signer_count)
        .map(|_| generate_keypair(SphincsVariant::SPX256f).expect("keypair"))
        .collect();
    let pks: Vec<Vec<u8>> = keys.iter().map(|k| k.public_key.clone()).collect();
    let proto = policy_bytes(&pks, 2, true, true, true, &[]);
    let policy_commit = policy_commit_of(&proto);
    let op = Operation::Mint {
        amount: Balance::from_state(amount, [0u8; 32]),
        token_id: b"NEW".to_vec(),
        policy_commit,
        message: String::new(),
    };
    let op_digest = dsm::economic::faucet::dsm_operation_digest(&op.to_bytes());
    let body = IssuanceAuthorizationBody {
        policy_commit,
        issuer_genesis: G,
        issuer_devid: DEV,
        issuer_economic_position: POSITION,
        recipient_operation_digest: op_digest,
        amount,
    };
    let body_ccb = body.encode().expect("body ccb");
    let digest = body.signing_digest().expect("signing digest");
    let stranger = generate_keypair(SphincsVariant::SPX256f).expect("keypair");
    let signatures = vec![
        generated::PolicySignerSignatureV1 {
            signer_public_key: keys[0].public_key.clone(),
            signature: sphincs_sign(&keys[0].secret_key, &digest).expect("sign"),
        },
        // Valid signature, correct digest, key the policy never named.
        generated::PolicySignerSignatureV1 {
            signer_public_key: stranger.public_key.clone(),
            signature: sphincs_sign(&stranger.secret_key, &digest).expect("sign"),
        },
    ];
    let evidence_bytes = generated::IssuanceAuthorizationEvidenceV1 {
        canonical_policy_bytes: proto,
        authorization_body_ccb: body_ccb,
        signatures,
    }
    .encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ISSUANCE_AUTHORIZATION_EVIDENCE,
        &evidence_bytes,
    );
    let mut tree = EconomicSmt::new();
    let balances = BTreeMap::new();
    let built = build_write_set(
        &op,
        &G,
        &DEV,
        &[0x42u8; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::AuthorizedIssuance {
            issuance_authorization_addr: evidence_addr,
        },
    )
    .expect("builder");
    let witness = EconomicTransitionWitness::new(
        [0u8; 32],
        built.post_root,
        [0x42u8; 32],
        op_digest,
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    Fixture {
        op,
        witness,
        evidence_addr,
        evidence_bytes,
        policy_commit,
    }
}

fn ctx_for(op: &Operation) -> ProvenanceContext<'_> {
    ProvenanceContext {
        genesis: &G,
        device_id: &DEV,
        economic_position: POSITION,
        network_id: b"dsm-testnet",
        proven_ak: &[0xAB; 64],
        canonical_storage_set_id: [0x6B; 32],
        substrate_b_pair: None,
        verified_operation: Some(op),
    }
}

fn resolver(fx: &Fixture) -> IssuanceResolver {
    IssuanceResolver {
        evidence_addr: fx.evidence_addr,
        evidence_bytes: fx.evidence_bytes.clone(),
    }
}

fn refusal(fx: &Fixture, r: &IssuanceResolver, op: &Operation, needle: &str) {
    let ctx = ctx_for(op);
    match verify_transition_provenance(&fx.witness, r, &ctx) {
        Err(ProvenanceError::AuthorizedIssuanceInvalid(m)) => assert!(
            m.contains(needle),
            "refusal should name {needle:?}, got: {m}"
        ),
        other => panic!("expected an issuance refusal naming {needle:?}, got {other:?}"),
    }
}

/// THE HONEST PATH: 2 distinct policy signers over the exact issuance, and the
/// credit is funded for exactly the operation's units.
#[test]
fn two_distinct_policy_signers_fund_the_exact_issuance() {
    let fx = fixture(3, 2, 1_000, true, true, &[], true);
    let funded = verify_transition_provenance(&fx.witness, &resolver(&fx), &ctx_for(&fx.op))
        .expect("a 2-of-3 authorized issuance verifies");
    assert_eq!(funded.len(), 1);
    assert_eq!(funded[0].amount, 1_000, "exactly the authorized units");
    assert_eq!(funded[0].policy_commit, fx.policy_commit);
}

/// ONE signature does not satisfy a 2-of-3 threshold.
#[test]
fn a_single_signature_does_not_meet_the_threshold() {
    let fx = fixture(3, 1, 1_000, true, true, &[], true);
    refusal(&fx, &resolver(&fx), &fx.op, "threshold");
}

/// CONSUME-ONCE, THE WAY IT ACTUALLY GETS ATTACKED: the SAME authorization
/// bytes, replayed against a second admission at the next economic position.
///
/// The operation digest is identical, so "the digest differs" would not save
/// us — the position is what does. The signed body names the position it was
/// authorized for, and the verifier requires equality with the position under
/// validation.
#[test]
fn the_same_authorization_bytes_cannot_fund_a_second_credit() {
    let fx = fixture(3, 2, 1_000, true, true, &[], true);
    // First admission verifies at the authorized position.
    verify_transition_provenance(&fx.witness, &resolver(&fx), &ctx_for(&fx.op))
        .expect("first issuance verifies");

    // Same witness, same evidence, same operation — next position.
    let mut ctx = ctx_for(&fx.op);
    ctx.economic_position = POSITION + 1;
    match verify_transition_provenance(&fx.witness, &resolver(&fx), &ctx) {
        Err(ProvenanceError::AuthorizedIssuanceInvalid(m)) => assert!(
            m.contains("economic position"),
            "the replay must fail on the position, got: {m}"
        ),
        other => panic!("replayed authorization must be refused, got {other:?}"),
    }
}

/// The authorization names an amount; issuing a different one is refused even
/// though every signature is valid.
#[test]
fn an_amount_the_authorization_does_not_name_is_refused() {
    let fx = fixture(3, 2, 1_000, true, true, &[], true);
    let tampered = match &fx.op {
        Operation::Mint {
            policy_commit,
            token_id,
            ..
        } => Operation::Mint {
            amount: Balance::from_state(1_001, [0u8; 32]),
            token_id: token_id.clone(),
            policy_commit: *policy_commit,
            message: String::new(),
        },
        _ => unreachable!(),
    };
    refusal(&fx, &resolver(&fx), &tampered, "different issuance");
}

/// A different asset is a different issuance, however valid the signatures.
#[test]
fn a_policy_commit_the_authorization_does_not_name_is_refused() {
    let fx = fixture(3, 2, 1_000, true, true, &[], true);
    let tampered = match &fx.op {
        Operation::Mint {
            amount, token_id, ..
        } => Operation::Mint {
            amount: amount.clone(),
            token_id: token_id.clone(),
            policy_commit: [0xEE; 32],
            message: String::new(),
        },
        _ => unreachable!(),
    };
    refusal(&fx, &resolver(&fx), &tampered, "policy");
}

/// A FINITE SUPPLY CAP IS REFUSED, not ignored. Its circulating input is
/// per-device, so N authorized devices would each mint to the ceiling.
#[test]
fn a_finite_supply_cap_refuses_the_issuance() {
    let fx = fixture(3, 2, 1_000, false, true, &[], true);
    refusal(&fx, &resolver(&fx), &fx.op, "SupplyCap");
}

/// The committed policy says mint/burn is disabled. Issuing under it anyway
/// would authorize the act the policy forbids.
#[test]
fn a_policy_with_mint_burn_disabled_refuses_the_issuance() {
    let fx = fixture(3, 2, 1_000, true, false, &[], true);
    refusal(&fx, &resolver(&fx), &fx.op, "disables mint/burn");
}

/// THE ALLOWLIST BINDS THE RECEIVING DEVICE. A device outside the committed
/// allowlist cannot receive the credit, even with a full valid threshold.
#[test]
fn a_device_outside_the_committed_allowlist_is_refused() {
    let fx = fixture(3, 2, 1_000, true, true, &[[0x77u8; 32]], true);
    refusal(&fx, &resolver(&fx), &fx.op, "allowlist");

    // Positive control: the SAME policy shape naming this device admits it, so
    // the refusal above is the allowlist rule and not a broken fixture.
    let ok = fixture(3, 2, 1_000, true, true, &[DEV], true);
    verify_transition_provenance(&ok.witness, &resolver(&ok), &ctx_for(&ok.op))
        .expect("an allowlisted device may receive the issuance");
}

/// AN AUTHORITY NOBODY CAN SATISFY AUTHORIZES NOTHING.
///
/// The committed v3 blob always carries a threshold and a signer count, so a
/// policy with no authority AT ALL is not expressible — the reachable shape is
/// an authority whose own signer set cannot meet its threshold. Refused, not
/// ignored: the absence of a denial is never permission. The signing keys here
/// are real and their signatures valid, so the refusal is the policy's, not a
/// missing-signature artifact.
#[test]
fn an_authority_its_own_signer_set_cannot_satisfy_refuses_the_issuance() {
    let fx = fixture(1, 1, 1_000, true, true, &[], false);
    refusal(
        &fx,
        &resolver(&fx),
        &fx.op,
        "not satisfiable by its own signer set",
    );

    // Positive control: the same shape with a satisfiable authority verifies.
    let ok = fixture(2, 2, 1_000, true, true, &[], true);
    verify_transition_provenance(&ok.witness, &resolver(&ok), &ctx_for(&ok.op))
        .expect("a satisfiable authority admits the issuance");
}

// `a_mint_carrying_its_own_authorization_is_refused` was DELETED with the
// channel it guarded: `Operation::Mint` no longer has authorization fields,
// so an authorization riding inside the operation is unrepresentable — the
// type system now enforces what that test asserted at runtime.
/// Tampered evidence bytes do not hash to the descriptor's address.
#[test]
fn tampered_evidence_is_refused_by_address() {
    let fx = fixture(3, 2, 1_000, true, true, &[], true);
    let mut bad = fx.evidence_bytes.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    let r = IssuanceResolver {
        evidence_addr: fx.evidence_addr,
        evidence_bytes: bad,
    };
    refusal(&fx, &r, &fx.op, "hash to the descriptor's address");
}

/// A valid signature from a key the POLICY DOES NOT NAME is not a signer.
///
/// The stranger signs the correct digest correctly, and the bundle is built
/// with that signature from the start so its ADDRESS matches the descriptor —
/// otherwise this would merely re-test the address check. What is left is
/// exactly the question: does the arm count a signature whose key the policy
/// never named? It must not, so a 2-of-3 policy sees only ONE real signer.
#[test]
fn a_signature_from_an_unnamed_key_does_not_count() {
    let fx = fixture_with_stranger(3, 1_000);
    refusal(&fx, &resolver(&fx), &fx.op, "threshold");
}

/// Positive control for the test above: the identical fixture shape with the
/// stranger replaced by a genuine policy signer verifies. Without this, the
/// refusal above could be any unrelated defect in the stranger fixture.
#[test]
fn the_same_fixture_with_a_named_second_signer_verifies() {
    let fx = fixture(3, 2, 1_000, true, true, &[], true);
    verify_transition_provenance(&fx.witness, &resolver(&fx), &ctx_for(&fx.op))
        .expect("two named signers meet the threshold");
}

/// The beta fleet as a catalog resolves it: the network's canonical member
/// ids paired with the register incarnations those members are serving.
///
/// A set id is a function of `(member_id, register_incarnation_id)` pairs, so
/// a fixture cannot state one as a constant — it derives it the same way
/// production does, from candidate entries the profile then checks.
fn beta_candidate_set() -> dsm::ccb::StorageSetMembers {
    // Built from the network's PINNED pairs, so a fixture resolves to the
    // real committed register rather than to values a fixture chose.
    let pinned = dsm::economic::register::pinned_root_register_members(b"dsm-testnet")
        .expect("the beta network is known");
    dsm::ccb::StorageSetMembers::new(pinned).expect("pinned beta set")
}
