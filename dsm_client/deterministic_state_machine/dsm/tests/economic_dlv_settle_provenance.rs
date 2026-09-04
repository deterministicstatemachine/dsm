// SPDX-License-Identifier: Apache-2.0

//! The 0x0026 (`DlvReserveConsumption`) provenance arm, end to end on a real
//! fixture: a trader's `DlvSettle` write set built by the REAL builder, an
//! owner vault state `V_n` whose `c_n` the settle binds, a replayable
//! vault-bound owner authority evidence, both reserve pre-leaves proven into
//! the owner's validated economic root, a SPHINCS+-signed RouteCommit whose
//! hop binds `c_n`, and the v2 settlement-slot winner binding the same state.
//!
//! Every MC-SETTLE control mutates ONE input of the honest fixture and
//! requires the named refusal — the arm's conjunctions are each load-bearing.

#![allow(clippy::disallowed_methods)]

use dsm::ccb::{
    storage_set_id, vault_state_commitment, EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy,
    StorageSetMembers, VaultStateV2,
};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{
    verify_transition_provenance, FaucetTicketWin, PeerLineageFailure, ProvenanceContext,
    ProvenanceError, ProvenanceResolver, SettlementSlotWin, ValidatedPeerTransition,
};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState, EconomicVaultReserveState};
use dsm::economic::tree::{EconomicSmt, ECONOMIC_SMT_HEIGHT};
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::economic::write_set::{
    build_write_set, verify_operation_write_set, CreditSourceFacts, EconomicPreState,
};
use dsm::types::operations::{Operation, TransactionMode};
use prost::Message;

const VAULT: [u8; 32] = [0x60; 32];
const G_TRADER: [u8; 32] = [0x71; 32];
const DEV_TRADER: [u8; 32] = [0x72; 32];
const PARENT: u64 = 4;
const OWNER_POSITION: u64 = 9;
const RESERVE_A: u64 = 100_000;
const RESERVE_B: u64 = 50_000;
const INPUT: u64 = 1_000;
const FEE_BPS: u32 = 30;

fn pc_a() -> [u8; 32] {
    [0x0A; 32]
}
fn pc_b() -> [u8; 32] {
    [0x0B; 32]
}

struct Keys {
    trader_pk: Vec<u8>,
    trader_sk: Vec<u8>,
}

fn keys() -> &'static Keys {
    static KEYS: std::sync::OnceLock<Keys> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        let (trader_pk, trader_sk) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("trader keypair");
        Keys {
            trader_pk,
            trader_sk,
        }
    })
}

/// A REAL owner identity with fully replayable vault-bound authority
/// evidence: genesis params, D_0 under the GRK, t_0 under the AK, the
/// single-device tree proof and the recomputable AttA — the exact material
/// `verify_authority_evidence` replays through P0–P6.
struct Owner {
    g: [u8; 32],
    devid: [u8; 32],
    ak_public: Vec<u8>,
    authority_evidence: Vec<u8>,
    t0_digest: [u8; 32],
}

fn owner() -> &'static Owner {
    static OWNER: std::sync::OnceLock<Owner> = std::sync::OnceLock::new();
    OWNER.get_or_init(|| {
        use dsm::ccb::{
            delegation_genesis_sentinel, role, sigalg, transition_genesis_sentinel,
            DeviceTreeRootTransition, GenesisParamsV3, RootProgressionDelegation,
        };
        use dsm::common::device_tree::DeviceTree;
        use dsm::core::identity::genesis_v2::derive_atta;
        use dsm::core::identity::genesis_v3::derive_genesis_v3_self_attested;

        let wallet_seed = [0x5Eu8; 32];
        let network_id: &[u8] = b"dsm-testnet";
        let aph = dsm::core::identity::genesis_session::genesis_authority_policy_hash();
        let genesis = derive_genesis_v3_self_attested(&wallet_seed, network_id, 0, 0, 3, &aph)
            .expect("owner genesis");
        let params = GenesisParamsV3::new(
            genesis.genesis_nonce,
            network_id,
            3,
            sigalg::SPHINCS_PLUS_SPX256F,
            &genesis.grk_public,
        )
        .expect("params");
        let d0 = RootProgressionDelegation {
            genesis_id: genesis.g,
            role: role::DEVICE_TREE_ROOT_PROGRESSION,
            role_version: role::BETA_ROLE_VERSION,
            delegated_alg_id: sigalg::SPHINCS_PLUS_SPX256F,
            delegated_pk: genesis.ak_public.clone(),
            delegation_number: 0,
            parent_delegation_digest: delegation_genesis_sentinel(),
            activation_transition_digest: transition_genesis_sentinel(),
        };
        let d0_sig = dsm::crypto::sphincs::sphincs_sign(
            &genesis.grk_secret,
            &d0.signing_digest().expect("d0 signing digest"),
        )
        .expect("sign d0");
        let tree = DeviceTree::single(genesis.devid);
        let t0 = DeviceTreeRootTransition {
            genesis_id: genesis.g,
            predecessor_transition_digest: transition_genesis_sentinel(),
            new_root: tree.root(),
            version_number: 0,
            delegation_digest: d0.digest().expect("d0 digest"),
        };
        let t0_sig = dsm::crypto::sphincs::sphincs_sign(&genesis.ak_secret, &t0.signing_digest())
            .expect("sign t0");
        let t0_digest = t0.digest();
        let proof = tree.proof(&genesis.devid).expect("tree proof");
        let atta = derive_atta(&wallet_seed, &genesis.g, 0);
        let evidence = dsm::types::proto::AuthorityEvidenceV1 {
            genesis_params_ccb: params.encode().expect("params encode"),
            delegations: vec![dsm::types::proto::SignedAuthorityObjectV1 {
                ccb: d0.encode().expect("d0 encode"),
                signature: d0_sig,
            }],
            transitions: vec![dsm::types::proto::SignedAuthorityObjectV1 {
                ccb: t0.encode(),
                signature: t0_sig,
            }],
            inclusion_proof: proof.to_bytes(),
            ak_public_key: genesis.ak_public.clone(),
            atta: atta.to_vec(),
        };
        Owner {
            g: genesis.g,
            devid: genesis.devid,
            ak_public: genesis.ak_public.clone(),
            authority_evidence: evidence.encode_to_vec(),
            t0_digest,
        }
    })
}

/// Everything the honest settle needs, precomputed once.
struct Fixture {
    output: u64,
    vn: VaultStateV2,
    c_n: [u8; 32],
    vault_set_id: [u8; 32],
    owner_root: [u8; 32],
    /// (state, siblings) per leg, proven into `owner_root`.
    reserve_a: (
        EconomicVaultReserveState,
        Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
    ),
    reserve_b: (
        EconomicVaultReserveState,
        Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
    ),
    route_commit_bytes: Vec<u8>,
    x: [u8; 32],
    slot_envelope: Vec<u8>,
    evidence_bytes: Vec<u8>,
    evidence_addr: [u8; 32],
    /// The owner's generic inclusion proof, and its address — what the bundle
    /// names instead of carrying leaves of its own.
    proof_bytes: Vec<u8>,
    proof_addr: [u8; 32],
    settle: Operation,
    witness: EconomicTransitionWitness,
}

fn sibling_array(tree: &EconomicSmt, key: &[u8; 32]) -> Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]> {
    let v = tree.siblings(key);
    let mut out = Box::new([[0u8; 32]; ECONOMIC_SMT_HEIGHT]);
    out.copy_from_slice(&v);
    out
}

/// The owner's generic inclusion proof for a set of reserve legs, and its
/// inner content address — the ONE proof source the 0x0026 bundle names.
fn owner_proof(
    tree: &EconomicSmt,
    g: &[u8; 32],
    devid: &[u8; 32],
    position: u64,
    legs: &[EconomicVaultReserveState],
) -> (Vec<u8>, [u8; 32]) {
    let leaves = legs
        .iter()
        .map(|l| {
            let state = EconomicLeafState::VaultReserve(l.clone());
            dsm::economic::proof_artifact::EconomicProofLeaf {
                siblings: sibling_array(tree, &state.leaf_key(g, devid)),
                state,
            }
        })
        .collect();
    let artifact = dsm::economic::proof_artifact::EconomicProofArtifact::new(
        *g,
        *devid,
        position,
        tree.root(),
        leaves,
    )
    .expect("the owner's proof artifact builds");
    let bytes = artifact.encode();
    let addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_ECONOMIC_PROOF_ARTIFACT,
        &bytes,
    );
    (bytes, addr)
}

fn fixture() -> Fixture {
    let k = keys();
    let ow = owner();
    let output =
        dsm::dlv::route_commit::constant_product_output(INPUT, RESERVE_A, RESERVE_B, FEE_BPS)
            .expect("re-sim output");

    // The owner's validated economic root: both reserve legs at PARENT.
    let mut owner_tree = EconomicSmt::new();
    let leg = |pc: [u8; 32], amount: u64| EconomicVaultReserveState {
        vault_id: VAULT,
        policy_commit: pc,
        amount,
        vault_sequence: PARENT,
    };
    let (leg_a, leg_b) = (leg(pc_a(), RESERVE_A), leg(pc_b(), RESERVE_B));
    for l in [&leg_a, &leg_b] {
        let state = EconomicLeafState::VaultReserve(l.clone());
        owner_tree.insert(
            state.leaf_key(&ow.g, &ow.devid),
            state.leaf_value().expect("leaf value"),
        );
    }
    let owner_root = owner_tree.root();
    let key_of = |l: &EconomicVaultReserveState| {
        EconomicLeafState::VaultReserve(l.clone()).leaf_key(&ow.g, &ow.devid)
    };
    let reserve_a = (leg_a.clone(), sibling_array(&owner_tree, &key_of(&leg_a)));
    let reserve_b = (leg_b.clone(), sibling_array(&owner_tree, &key_of(&leg_b)));

    // The exact parent vault state the settle consumes.
    let vn = VaultStateV2 {
        owner_genesis_id: ow.g,
        owner_device_id: ow.devid,
        vault_id: VAULT,
        generation: PARENT,
        reserve_a: RESERVE_A,
        reserve_b: RESERVE_B,
        market_policy: MarketPolicy::beta_constant_product(pc_a(), pc_b()).expect("pair"),
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(FEE_BPS).expect("fee"),
        encumbrances: EncumbranceSet::new(Vec::new()).expect("empty encumbrances"),
        iteration_budget: None,
        parent_state_commitment: [0x33; 32],
        owner_authority_transition_digest: ow.t0_digest,
        storage_set: StorageSetMembers::new(&[b"dsm-node-1", b"dsm-node-2", b"dsm-node-3"])
            .expect("set"),
        quorum: 2,
    };
    let c_n = vault_state_commitment(&vn).expect("c_n");
    let vault_set_id = storage_set_id(&vn.storage_set).expect("set id");

    // The signed RouteCommit whose hop binds c_n.
    let mut rc = dsm::types::proto::RouteCommitV1 {
        version: dsm::dlv::route_commit::ROUTE_COMMIT_VERSION,
        nonce: vec![0x44; 32],
        input_token: pc_a().to_vec(),
        output_token: pc_b().to_vec(),
        input_amount_u128: (INPUT as u128).to_be_bytes().to_vec(),
        expected_final_output_amount_u128: (output as u128).to_be_bytes().to_vec(),
        total_fee_bps: FEE_BPS as u64,
        hops: vec![dsm::types::proto::RouteCommitHopV1 {
            vault_id: VAULT.to_vec(),
            token_in: pc_a().to_vec(),
            token_out: pc_b().to_vec(),
            input_amount_u128: (INPUT as u128).to_be_bytes().to_vec(),
            expected_output_amount_u128: (output as u128).to_be_bytes().to_vec(),
            fee_bps: FEE_BPS,
            advertisement_digest: vec![0x55; 32],
            unlock_spec_digest: vec![0x56; 32],
            owner_public_key: owner().ak_public.clone(),
            parent_binding: c_n.to_vec(),
        }],
        initiator_public_key: k.trader_pk.clone(),
        initiator_signature: Vec::new(),
    };
    let canonical = dsm::dlv::route_commit::canonicalise_for_commitment(&rc).encode_to_vec();
    rc.initiator_signature =
        dsm::crypto::sphincs::sphincs_sign(&k.trader_sk, &canonical).expect("sign rc");
    let x = dsm::dlv::route_commit::compute_external_commitment(&rc);
    let route_commit_bytes = rc.encode_to_vec();

    // The v2 slot winner: keyed by name, bound to the state.
    let slot_envelope = dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim(
        &dsm::dlv::settlement_slot_claim::SettlementSlotClaimBody {
            vault_id: VAULT,
            parent_sequence: PARENT,
            x,
            claimant_public_key: k.trader_pk.clone(),
            storage_set_id: vault_set_id,
            parent_binding_c_n: c_n,
        },
        &k.trader_sk,
    )
    .expect("sign slot claim");

    // The owner's generic proof, and the bundle that NAMES it: exact
    // CCB(V_n), the vault-bound authority evidence, one address.
    let (proof_bytes, proof_addr) = owner_proof(
        &owner_tree,
        &ow.g,
        &ow.devid,
        OWNER_POSITION,
        &[leg_a.clone(), leg_b.clone()],
    );
    let evidence = dsm::types::proto::ReserveConsumptionEvidenceV1 {
        exact_vault_state_ccb: vn.encode().expect("vn encode"),
        owner_authority_evidence: ow.authority_evidence.clone(),
        economic_proof_addr: proof_addr.to_vec(),
    };
    let evidence_bytes = evidence.encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
        &evidence_bytes,
    );

    let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&VAULT, &x);
    let settle = Operation::DlvSettle {
        vault_id: VAULT.to_vec(),
        owner_public_key: ow.ak_public.clone(),
        owner_devid: ow.devid,
        owner_genesis: ow.g,
        input_policy_commit: pc_a(),
        output_policy_commit: pc_b(),
        parent_sequence: PARENT,
        parent_binding: c_n,
        route_commit_bytes,
        external_commitment_x: x,
        input_amount: INPUT,
        output_amount: output,
        fee_bps: FEE_BPS,
        sigma: [0x66; 32],
        settler_public_key: k.trader_pk.clone(),
        settler_devid: DEV_TRADER,
        settlement_receipt_id: receipt_id,
        signature: vec![0x77; 48],
        mode: TransactionMode::Unilateral,
    };

    // The trader's write set, built by the REAL builder.
    let mut trader_tree = EconomicSmt::new();
    let funded = EconomicLeafState::Balance(
        EconomicBalanceState::new(pc_a(), 5_000).expect("trader balance"),
    );
    trader_tree.insert(
        funded.leaf_key(&G_TRADER, &DEV_TRADER),
        funded.leaf_value().expect("leaf value"),
    );
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let pre_root = trader_tree.root();
    let built = build_write_set(
        &settle,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEE; 32],
        &EconomicPreState::balances_only(&balances),
        &mut trader_tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: evidence_addr,
        },
    )
    .expect("the settle write set builds");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&settle.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    verify_operation_write_set(&settle, &G_TRADER, &DEV_TRADER, &witness)
        .expect("exact-effect verifies");

    let route_commit_bytes = match &settle {
        Operation::DlvSettle {
            route_commit_bytes, ..
        } => route_commit_bytes.clone(),
        _ => unreachable!(),
    };
    Fixture {
        output,
        vn,
        c_n,
        vault_set_id,
        owner_root,
        reserve_a,
        reserve_b,
        route_commit_bytes,
        x,
        slot_envelope,
        evidence_bytes,
        evidence_addr,
        proof_bytes,
        proof_addr,
        settle,
        witness,
    }
}

/// The resolver: the owner's validated root at exactly OWNER_POSITION, the
/// frozen evidence bundle, and the slot winner. Everything else fails
/// closed.
struct SettleResolver {
    owner_root: [u8; 32],
    /// Every immutable object this fixture publishes, by inner address: the
    /// evidence bundle and the owner's proof artifact. Anything else fails
    /// closed, so a test that expects a fetch to miss gets a miss.
    objects: Vec<([u8; 32], Vec<u8>)>,
    slot_envelope: Option<Vec<u8>>,
}

impl SettleResolver {
    fn owner_vpt(&self) -> ValidatedPeerTransition {
        // Only `validated_root` (and the identity coords) matter to the
        // 0x0026 arm; the witness is a minimal valid placeholder.
        let ow = owner();
        // A DEBIT-shaped placeholder (a bare credit would be structurally
        // unfunded): pre 2 -> post 1 on a scratch tree.
        let mut t = EconomicSmt::new();
        let pre = EconomicLeafState::Balance(EconomicBalanceState::new([0x01; 32], 2).unwrap());
        let post = EconomicLeafState::Balance(EconomicBalanceState::new([0x01; 32], 1).unwrap());
        let key = pre.leaf_key(&ow.g, &ow.devid);
        t.insert(key, pre.leaf_value().unwrap());
        let pre_root = t.root();
        let siblings = t.siblings(&key).to_vec();
        let m = EconomicLeafMutation::new(Some(pre), Some(post.clone()), siblings).unwrap();
        t.insert(key, post.leaf_value().unwrap());
        let witness = EconomicTransitionWitness::new(
            pre_root,
            t.root(),
            [0x0E; 32],
            [0x0F; 32],
            vec![m],
            Vec::new(),
        )
        .unwrap();
        ValidatedPeerTransition {
            peer_genesis: ow.g,
            peer_devid: ow.devid,
            validated_root:
                dsm::economic::lineage::ValidatedEconomicRoot::rehydrate_from_admitted_store(
                    OWNER_POSITION,
                    self.owner_root,
                ),
            witness,
            proven_ak: ow.ak_public.clone(),
            c_dsm_plus: [0xC5; 32],
            verified_operation: Operation::Noop,
        }
    }
}

impl ProvenanceResolver for SettleResolver {
    fn validated_peer_transition(
        &self,
        peer_genesis: &[u8; 32],
        peer_devid: &[u8; 32],
        peer_economic_position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let ow = owner();
        if *peer_genesis == ow.g
            && *peer_devid == ow.devid
            && peer_economic_position == OWNER_POSITION
        {
            Ok(self.owner_vpt())
        } else {
            Err(PeerLineageFailure::Incomplete(
                "no such validated lineage".into(),
            ))
        }
    }

    fn winning_faucet_ticket(&self, _f: &[u8; 32], _i: u64) -> Option<FaucetTicketWin> {
        None
    }

    fn winning_settlement_slot_claim(
        &self,
        vault_id: &[u8; 32],
        parent_sequence: u64,
    ) -> Option<SettlementSlotWin> {
        if *vault_id == VAULT && parent_sequence == PARENT {
            self.slot_envelope
                .clone()
                .map(|envelope_bytes| SettlementSlotWin { envelope_bytes })
        } else {
            None
        }
    }

    fn immutable_evidence(
        &self,
        _namespace: dsm::crypto::domain::TaggedHashDomain<'static>,
        addr: &[u8; 32],
    ) -> Result<Vec<u8>, PeerLineageFailure> {
        match self.objects.iter().find(|(a, _)| a == addr) {
            Some((_, bytes)) => Ok(bytes.clone()),
            None => Err(PeerLineageFailure::Incomplete("unknown address".into())),
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

fn resolver_for(fx: &Fixture) -> SettleResolver {
    SettleResolver {
        owner_root: fx.owner_root,
        objects: vec![
            (fx.evidence_addr, fx.evidence_bytes.clone()),
            (fx.proof_addr, fx.proof_bytes.clone()),
        ],
        slot_envelope: Some(fx.slot_envelope.clone()),
    }
}

fn ctx_for<'a>(fx: &'a Fixture) -> ProvenanceContext<'a> {
    ProvenanceContext {
        genesis: &G_TRADER,
        device_id: &DEV_TRADER,
        economic_position: 3,
        network_id: b"dsm-testnet",
        proven_ak: &keys().trader_pk,
        canonical_storage_set_id: [0x6B; 32],
        substrate_b_pair: None,
        verified_operation: Some(&fx.settle),
    }
}

fn expect_reserve_refusal(
    fx: &Fixture,
    resolver: &SettleResolver,
    ctx: &ProvenanceContext<'_>,
    needle: &str,
) {
    match verify_transition_provenance(&fx.witness, resolver, ctx) {
        Err(ProvenanceError::DlvReserveConsumptionInvalid(m)) => {
            assert!(
                m.contains(needle),
                "expected {needle:?} in refusal, got: {m}"
            )
        }
        other => panic!("expected a reserve-consumption refusal ({needle}), got {other:?}"),
    }
}

// ── The honest fixture funds ───────────────────────────────────────────────

#[test]
fn a_real_settle_funds_through_every_conjunction() {
    let fx = fixture();
    let funded = verify_transition_provenance(&fx.witness, &resolver_for(&fx), &ctx_for(&fx))
        .expect("the honest settle is funded");
    assert_eq!(funded.len(), 1);
    assert_eq!(funded[0].policy_commit, pc_b());
    assert_eq!(funded[0].amount, fx.output);
}

// ── MC-SETTLE controls: one input mutated, one named refusal ───────────────

#[test]
fn a_missing_slot_winner_fails_closed() {
    // MC-SETTLE: the slot register is the liveness anchor — no quorum winner,
    // no funding.
    let fx = fixture();
    let mut r = resolver_for(&fx);
    r.slot_envelope = None;
    expect_reserve_refusal(
        &fx,
        &r,
        &ctx_for(&fx),
        "no quorum-agreed settlement-slot winner",
    );
}

#[test]
fn a_slot_winner_binding_a_different_parent_state_is_refused() {
    // MC-SETTLE-6 — the PR2 companion control: nodes accept any well-formed
    // claim, so the ARM is what refuses a winner bound to a different c_n.
    let fx = fixture();
    let k = keys();
    let mut r = resolver_for(&fx);
    r.slot_envelope = Some(
        dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim(
            &dsm::dlv::settlement_slot_claim::SettlementSlotClaimBody {
                vault_id: VAULT,
                parent_sequence: PARENT,
                x: fx.x,
                claimant_public_key: k.trader_pk.clone(),
                storage_set_id: fx.vault_set_id,
                parent_binding_c_n: [0xDD; 32],
            },
            &k.trader_sk,
        )
        .expect("sign divergent claim"),
    );
    expect_reserve_refusal(&fx, &r, &ctx_for(&fx), "slot winner does not bind");
}

#[test]
fn a_slot_winner_by_a_different_claimant_is_refused() {
    // MC-SETTLE-5: claimant == RouteCommit author == the trader under
    // validation. A rival's winning claim funds nothing for THIS trader.
    let fx = fixture();
    let (rival_pk, rival_sk) =
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("rival keypair");
    let mut r = resolver_for(&fx);
    r.slot_envelope = Some(
        dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim(
            &dsm::dlv::settlement_slot_claim::SettlementSlotClaimBody {
                vault_id: VAULT,
                parent_sequence: PARENT,
                x: fx.x,
                claimant_public_key: rival_pk,
                storage_set_id: fx.vault_set_id,
                parent_binding_c_n: fx.c_n,
            },
            &rival_sk,
        )
        .expect("sign rival claim"),
    );
    expect_reserve_refusal(&fx, &r, &ctx_for(&fx), "not the settling trader");
}

#[test]
fn an_unresolvable_owner_lineage_fails_closed_as_incomplete() {
    // MC-SETTLE-8: an outage is never funding, and never an attack either.
    let fx = fixture();
    let mut ctx = ctx_for(&fx);
    ctx.verified_operation = Some(&fx.settle);
    let mut r = resolver_for(&fx);
    r.owner_root = [0xAB; 32]; // resolvable, but the reserve proofs will fail
                               // The proposition is unchanged — a root the reserve proofs do not belong
                               // to funds nothing — but the refusal now arrives EARLIER and names the
                               // coordinate rather than the symptom. The artifact declares which root it
                               // proves into, so a root the arm derived that disagrees is rejected before
                               // a single path is recomputed; the old message came from discovering the
                               // mismatch one leaf at a time.
    expect_reserve_refusal(&fx, &r, &ctx, "names a different economic root");
}

#[test]
fn tampered_evidence_bytes_are_refused_by_address() {
    // MC-SETTLE-11: the descriptor's address IS the evidence identity.
    let fx = fixture();
    let mut r = resolver_for(&fx);
    let mut tampered = fx.evidence_bytes.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    r.objects.retain(|(a, _)| *a != fx.evidence_addr);
    r.objects.push((fx.evidence_addr, tampered));
    expect_reserve_refusal(
        &fx,
        &r,
        &ctx_for(&fx),
        "do not hash to the descriptor's address",
    );
}

#[test]
fn the_settle_operation_is_cross_checked_field_by_field() {
    // One honest witness, verified against one-bit-off settle operations
    // supplied as the context's verified operation: MC-SETTLE-3 (c_n),
    // MC-SETTLE-10 (X), the amount clauses (re-sim, MC-SETTLE-4), and the
    // settler identity.
    let fx = fixture();
    let r = resolver_for(&fx);

    let mutate = |f: &dyn Fn(&mut Operation)| {
        let mut op = fx.settle.clone();
        f(&mut op);
        op
    };
    let cases: Vec<(Operation, &str)> = vec![
        (
            mutate(&|op| {
                if let Operation::DlvSettle { parent_binding, .. } = op {
                    *parent_binding = [0xDC; 32];
                }
            }),
            // The carried CCB(V_n) no longer hashes to the claimed binding.
            "does not hash to the settle's parent binding",
        ),
        (
            mutate(&|op| {
                if let Operation::DlvSettle {
                    external_commitment_x,
                    ..
                } = op
                {
                    *external_commitment_x = [0xDB; 32];
                }
            }),
            // The witness's descriptor was built from the honest op, so the
            // coordinate equality breaks first — X is singly-sourced.
            "descriptor coordinates do not equal the operation's",
        ),
        (
            mutate(&|op| {
                if let Operation::DlvSettle { output_amount, .. } = op {
                    *output_amount += 1;
                }
            }),
            // The signed hop states the exact trade; +1 is not it.
            "the bound hop does not state the settle's exact trade",
        ),
        (
            mutate(&|op| {
                if let Operation::DlvSettle {
                    settler_public_key, ..
                } = op
                {
                    settler_public_key[0] ^= 0xFF;
                }
            }),
            "not the identity under validation",
        ),
    ];
    for (op, needle) in &cases {
        let mut ctx = ctx_for(&fx);
        ctx.verified_operation = Some(op);
        match verify_transition_provenance(&fx.witness, &r, &ctx) {
            Err(ProvenanceError::DlvReserveConsumptionInvalid(m)) => assert!(
                m.contains(needle),
                "expected {needle:?} in refusal, got: {m}"
            ),
            other => panic!("expected refusal ({needle}), got {other:?}"),
        }
    }
}

#[test]
fn a_second_settle_on_the_same_parent_is_refused_at_build() {
    // MC-SETTLE-12: the receipt leaf is write-once — replaying the SAME
    // settle against the post-state tree fails its own Merkle precondition.
    let fx = fixture();
    let mut tree = EconomicSmt::new();
    // Reconstruct the trader's POST state: replay the witness mutations.
    let funded = EconomicLeafState::Balance(
        EconomicBalanceState::new(pc_a(), 5_000).expect("trader balance"),
    );
    tree.insert(
        funded.leaf_key(&G_TRADER, &DEV_TRADER),
        funded.leaf_value().expect("leaf value"),
    );
    for m in &fx.witness.mutations {
        let key = m.leaf_key(&G_TRADER, &DEV_TRADER).expect("key");
        match &m.post_state {
            Some(s) => tree.insert(key, s.leaf_value().expect("value")),
            None => tree.remove(&key),
        }
    }
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64 - INPUT);
    balances.insert(pc_b(), fx.output);
    let err = build_write_set(
        &fx.settle,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEF; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: fx.evidence_addr,
        },
    )
    .expect_err("a second settle on the same (vault, x) must refuse");
    assert!(
        err.to_string().contains("already exists"),
        "the refusal is the write-once receipt leaf, got: {err}"
    );
}

#[test]
fn a_receipt_id_that_does_not_derive_from_vault_and_x_is_refused() {
    // MC-SETTLE-2, at derivation: the receipt id is a NAME for (vault, x).
    let fx = fixture();
    let mut op = fx.settle.clone();
    if let Operation::DlvSettle {
        settlement_receipt_id,
        ..
    } = &mut op
    {
        settlement_receipt_id[0] ^= 0xFF;
    }
    let mut tree = EconomicSmt::new();
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let err = build_write_set(
        &op,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEE; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: fx.evidence_addr,
        },
    )
    .expect_err("a mismatched receipt id must refuse");
    assert!(
        err.to_string().contains("does not derive from"),
        "got: {err}"
    );
}

#[test]
fn an_insufficient_output_reserve_is_refused() {
    // MC-SETTLE-7: a vault that cannot pay has not settled this trade —
    // proven with a bundle/owner-root whose output reserve is BELOW the
    // authorized output while the re-simulated arithmetic is kept exact by
    // scaling the trade, not the check.
    let fx = fixture();
    // Rebuild an owner world whose output leg is tiny, then reuse the honest
    // op but with resolver facts pointing at the poor world — every clause
    // before sufficiency must pass, so tamper ONLY the reserve amounts is
    // not possible without breaking V_n equality; instead prove the clause
    // directly: the arm compares the PROVEN leaves to V_n, so shrink both
    // consistently and let the re-sim mismatch name the refusal.
    let ow = owner();
    let mut vn = fx.vn.clone();
    vn.reserve_b = fx.output - 1;
    let mut owner_tree = EconomicSmt::new();
    let leg_a = fx.reserve_a.0.clone();
    let mut leg_b = fx.reserve_b.0.clone();
    leg_b.amount = fx.output - 1;
    for l in [&leg_a, &leg_b] {
        let state = EconomicLeafState::VaultReserve(l.clone());
        owner_tree.insert(
            state.leaf_key(&ow.g, &ow.devid),
            state.leaf_value().expect("leaf value"),
        );
    }
    let c_n = vault_state_commitment(&vn).expect("c_n");
    // The settle now binds the poor state's identity, so the bundle and the
    // op stay mutually consistent up to the sufficiency clause.
    let mut op = fx.settle.clone();
    if let Operation::DlvSettle { parent_binding, .. } = &mut op {
        *parent_binding = c_n;
    }
    let (proof_bytes, proof_addr) = owner_proof(
        &owner_tree,
        &ow.g,
        &ow.devid,
        OWNER_POSITION,
        &[leg_a.clone(), leg_b.clone()],
    );
    let evidence = dsm::types::proto::ReserveConsumptionEvidenceV1 {
        exact_vault_state_ccb: vn.encode().expect("vn encode"),
        owner_authority_evidence: ow.authority_evidence.clone(),
        economic_proof_addr: proof_addr.to_vec(),
    };
    let evidence_bytes = evidence.encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
        &evidence_bytes,
    );
    // Rebuild the trader witness against the tampered op so the descriptor
    // stays singly-sourced (same X, same coordinates — only c_n moved).
    let mut tree = EconomicSmt::new();
    let funded =
        EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 5_000).expect("balance"));
    tree.insert(
        funded.leaf_key(&G_TRADER, &DEV_TRADER),
        funded.leaf_value().expect("value"),
    );
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let pre_root = tree.root();
    let built = build_write_set(
        &op,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEE; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: evidence_addr,
        },
    )
    .expect("builds");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&op.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    let resolver = SettleResolver {
        owner_root: owner_tree.root(),
        objects: vec![(evidence_addr, evidence_bytes), (proof_addr, proof_bytes)],
        slot_envelope: Some(fx.slot_envelope.clone()),
    };
    let mut ctx = ctx_for(&fx);
    ctx.verified_operation = Some(&op);
    match verify_transition_provenance(&witness, &resolver, &ctx) {
        Err(ProvenanceError::DlvReserveConsumptionInvalid(m)) => assert!(
            m.contains("cannot pay that settlement output"),
            "expected the sufficiency refusal, got: {m}"
        ),
        other => panic!("expected the sufficiency refusal, got {other:?}"),
    }
}

#[test]
fn an_artifact_proving_another_generation_selects_nothing() {
    // THE SELECTION CONTROL. A valid proof by the same owner, of the same
    // vault, at a DIFFERENT generation is a valid proof of something else.
    // The arm selects by exact vault and exact generation, so it finds no
    // legs at all rather than the nearest usable pair — a settlement is never
    // funded by evidence about another state.
    let fx = fixture();
    let ow = owner();
    let mut owner_tree = EconomicSmt::new();
    let mut leg_a = fx.reserve_a.0.clone();
    let mut leg_b = fx.reserve_b.0.clone();
    leg_a.vault_sequence += 1;
    leg_b.vault_sequence += 1;
    for l in [&leg_a, &leg_b] {
        let state = EconomicLeafState::VaultReserve(l.clone());
        owner_tree.insert(
            state.leaf_key(&ow.g, &ow.devid),
            state.leaf_value().expect("leaf value"),
        );
    }
    let (proof_bytes, proof_addr) = owner_proof(
        &owner_tree,
        &ow.g,
        &ow.devid,
        OWNER_POSITION,
        &[leg_a.clone(), leg_b.clone()],
    );
    let evidence = dsm::types::proto::ReserveConsumptionEvidenceV1 {
        exact_vault_state_ccb: fx.vn.encode().expect("vn encode"),
        owner_authority_evidence: ow.authority_evidence.clone(),
        economic_proof_addr: proof_addr.to_vec(),
    };
    let evidence_bytes = evidence.encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
        &evidence_bytes,
    );
    let mut tree = EconomicSmt::new();
    let funded =
        EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 5_000).expect("balance"));
    tree.insert(
        funded.leaf_key(&G_TRADER, &DEV_TRADER),
        funded.leaf_value().expect("value"),
    );
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let pre_root = tree.root();
    let built = build_write_set(
        &fx.settle,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEE; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: evidence_addr,
        },
    )
    .expect("builds");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&fx.settle.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    let resolver = SettleResolver {
        owner_root: owner_tree.root(),
        objects: vec![(evidence_addr, evidence_bytes), (proof_addr, proof_bytes)],
        slot_envelope: Some(fx.slot_envelope.clone()),
    };
    match verify_transition_provenance(&witness, &resolver, &ctx_for(&fx)) {
        Err(ProvenanceError::DlvReserveConsumptionInvalid(m)) => assert!(
            m.contains("not the pair this settlement consumes"),
            "expected the selection refusal, got: {m}"
        ),
        other => panic!("expected the selection refusal, got {other:?}"),
    }
}

#[test]
fn proven_leaves_that_disagree_with_v_n_are_refused() {
    // THE AMOUNT CONTROL. The artifact here is honest in every structural
    // sense — a real tree, real paths, verifying against the root the arm
    // derives — and it proves a reserve the vault state does not state. Two
    // representations of one fact may not disagree, so the arm refuses even
    // though nothing about the proof itself is malformed.
    let fx = fixture();
    let ow = owner();
    let mut owner_tree = EconomicSmt::new();
    let mut leg_a = fx.reserve_a.0.clone();
    leg_a.amount += 1; // one unit more than V_n states
    let leg_b = fx.reserve_b.0.clone();
    for l in [&leg_a, &leg_b] {
        let state = EconomicLeafState::VaultReserve(l.clone());
        owner_tree.insert(
            state.leaf_key(&ow.g, &ow.devid),
            state.leaf_value().expect("leaf value"),
        );
    }
    let (proof_bytes, proof_addr) = owner_proof(
        &owner_tree,
        &ow.g,
        &ow.devid,
        OWNER_POSITION,
        &[leg_a.clone(), leg_b.clone()],
    );
    let evidence = dsm::types::proto::ReserveConsumptionEvidenceV1 {
        exact_vault_state_ccb: fx.vn.encode().expect("vn encode"),
        owner_authority_evidence: ow.authority_evidence.clone(),
        economic_proof_addr: proof_addr.to_vec(),
    };
    let evidence_bytes = evidence.encode_to_vec();
    let evidence_addr = dsm::storage_object::immutable_inner(
        dsm::common::domain_tags::TAG_DSM_DLV_RESERVE_CONSUMPTION_EVIDENCE,
        &evidence_bytes,
    );
    // The trader witness, singly sourced from the new evidence address.
    let mut tree = EconomicSmt::new();
    let funded =
        EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 5_000).expect("balance"));
    tree.insert(
        funded.leaf_key(&G_TRADER, &DEV_TRADER),
        funded.leaf_value().expect("value"),
    );
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let pre_root = tree.root();
    let built = build_write_set(
        &fx.settle,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEE; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: evidence_addr,
        },
    )
    .expect("builds");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&fx.settle.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    let resolver = SettleResolver {
        owner_root: owner_tree.root(),
        objects: vec![(evidence_addr, evidence_bytes), (proof_addr, proof_bytes)],
        slot_envelope: Some(fx.slot_envelope.clone()),
    };
    match verify_transition_provenance(&witness, &resolver, &ctx_for(&fx)) {
        Err(ProvenanceError::DlvReserveConsumptionInvalid(m)) => assert!(
            m.contains("disagree with V_n's reserves"),
            "expected the disagreement refusal, got: {m}"
        ),
        other => panic!("expected the disagreement refusal, got {other:?}"),
    }
}

#[test]
fn an_over_paying_trade_is_refused_by_re_simulation_alone() {
    // MC-SETTLE-4, isolated: the trader SIGNS everything — the RouteCommit,
    // the settle, the slot claim — all mutually consistent, claiming an
    // output larger than the curve pays. Every byte-equality holds; ONLY the
    // independent constant-product re-simulation refuses.
    let fx = fixture();
    let k = keys();
    let ow = owner();
    let inflated = fx.output + 500; // still well below RESERVE_B

    let mut rc = <dsm::types::proto::RouteCommitV1 as prost::Message>::decode(
        fx.route_commit_bytes.as_slice(),
    )
    .expect("rc decodes");
    rc.hops[0].expected_output_amount_u128 = (inflated as u128).to_be_bytes().to_vec();
    rc.expected_final_output_amount_u128 = (inflated as u128).to_be_bytes().to_vec();
    rc.initiator_signature.clear();
    let canonical = dsm::dlv::route_commit::canonicalise_for_commitment(&rc).encode_to_vec();
    rc.initiator_signature =
        dsm::crypto::sphincs::sphincs_sign(&k.trader_sk, &canonical).expect("re-sign rc");
    let x = dsm::dlv::route_commit::compute_external_commitment(&rc);
    let receipt_id = dsm::dlv::settlement_receipt_leaf::derive_receipt_id(&VAULT, &x);

    let mut op = fx.settle.clone();
    if let Operation::DlvSettle {
        route_commit_bytes,
        external_commitment_x,
        output_amount,
        settlement_receipt_id,
        ..
    } = &mut op
    {
        *route_commit_bytes = rc.encode_to_vec();
        *external_commitment_x = x;
        *output_amount = inflated;
        *settlement_receipt_id = receipt_id;
    }
    let slot_envelope = dsm::dlv::settlement_slot_claim::sign_settlement_slot_claim(
        &dsm::dlv::settlement_slot_claim::SettlementSlotClaimBody {
            vault_id: VAULT,
            parent_sequence: PARENT,
            x,
            claimant_public_key: k.trader_pk.clone(),
            storage_set_id: fx.vault_set_id,
            parent_binding_c_n: fx.c_n,
        },
        &k.trader_sk,
    )
    .expect("sign slot claim");
    let _ = ow;

    // Rebuild the trader witness for the inflated op.
    let mut tree = EconomicSmt::new();
    let funded =
        EconomicLeafState::Balance(EconomicBalanceState::new(pc_a(), 5_000).expect("balance"));
    tree.insert(
        funded.leaf_key(&G_TRADER, &DEV_TRADER),
        funded.leaf_value().expect("value"),
    );
    let mut balances = std::collections::BTreeMap::new();
    balances.insert(pc_a(), 5_000u64);
    let pre_root = tree.root();
    let built = build_write_set(
        &op,
        &G_TRADER,
        &DEV_TRADER,
        &[0xEE; 32],
        &EconomicPreState::balances_only(&balances),
        &mut tree,
        &CreditSourceFacts::DlvReserveConsumption {
            owner_economic_position: OWNER_POSITION,
            reserve_consumption_evidence_addr: fx.evidence_addr,
        },
    )
    .expect("builds");
    let witness = EconomicTransitionWitness::new(
        pre_root,
        built.post_root,
        [0xEE; 32],
        dsm::economic::faucet::dsm_operation_digest(&op.to_bytes()),
        built.mutations,
        built.credit_sources,
    )
    .expect("witness");
    let mut resolver = resolver_for(&fx);
    resolver.slot_envelope = Some(slot_envelope);
    let mut ctx = ctx_for(&fx);
    ctx.verified_operation = Some(&op);
    match verify_transition_provenance(&witness, &resolver, &ctx) {
        Err(ProvenanceError::DlvReserveConsumptionInvalid(m)) => assert!(
            m.contains("re-simulation does not yield"),
            "expected the re-sim refusal ALONE, got: {m}"
        ),
        other => panic!("expected the re-sim refusal, got {other:?}"),
    }
}
