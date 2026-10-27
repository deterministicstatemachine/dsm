//! Every live object class has one canonical encoding (MR-DSM-0100).
//!
//! The classes are read from [`super::class`] itself, so a class added there
//! without an entry here fails, and an entry here naming a class that is not
//! live fails. Each entry is one object built through the production
//! constructor and encoded by the production encoder, and says how
//! production reads that class:
//!
//! - **Parsed**: production's own parser for the class reads the bytes back
//!   and re-encodes them to exactly those bytes, so no other byte string
//!   parses to the same object. The bytes with one more byte, every
//!   truncation, and the bytes under a class nothing parses are refused.
//! - **Nested**: production parses the class only inside an enclosing
//!   object, so the bytes must appear inside that object's Parsed bytes.
//! - **Hashed**: production never parses the class and only takes a digest
//!   of it, so the digest production computes must be the domain hash over
//!   exactly these bytes.
use std::collections::BTreeMap;

use crate::ccb::decode::{
    decode_fee_policy, decode_market_policy, decode_release_policy, Cursor, DecodeError,
};
use crate::ccb::{
    burned_class, class, decode_delegation, decode_genesis_params, decode_transition,
    decode_vault_state, role, sigalg, CcbObject, DeviceTreeRootTransition, EncumbranceClaim,
    EncumbranceSet, FeePolicy, GenesisParamsV3, MarketPolicy, ReleasePolicy,
    RootProgressionDelegation, StorageSetMembers, VaultStateV2,
};
use crate::common::domain_tags::{
    TAG_DSM_SOFI_RESOLUTION_CLAIM_SIGN, TAG_DSM_SOFI_ROUTE_DIGEST, TAG_DSM_SOFI_ROUTE_LEG_SET,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use crate::economic::claim::{AdmissionSubstrate, EconomicAdmissionManifest, EconomicRootClaimBody};
use crate::economic::claim_envelope::decode_economic_root_claim_body;
use crate::economic::credit::{
    CreditSource, CreditSourceGenesisRelease, CreditSourceNativeReserveRelease,
    CreditSourceOfflineBoundaryDebit, CreditSourceValidatedPeerDebit,
};
use crate::economic::decode::{
    decode_admission_manifest, decode_credit_source, decode_leaf_mutation, decode_leaf_state,
    decode_transition_witness,
};
use crate::economic::mutation::EconomicLeafMutation;
use crate::economic::offline_boundary::OfflineBoundaryBody;
use crate::economic::state::{
    EconomicBalanceState, EconomicConsumedSourceState, EconomicLeafState,
    EconomicTokenCreationState,
};
use crate::economic::witness::EconomicTransitionWitness;
use crate::merkle::smt_path::EncodedPath;
use crate::shared_lineage::{
    BundleStep, CheckpointV1, GenerationHintV1, LineageKind, SharedGenerationV1, SharedGenesisV1,
    TransitionBundleV1, EPOCH_GENERATIONS,
};
use crate::sofi::derive::{
    dlv_core_digest, precommit_id, resolution_claim_signing_digest, route_digest,
    route_leg_set_digest, trader_core_digest,
};
use crate::sofi::wire::{
    AttemptEntry, ComputedBranch, ComputedEscrowTerms, ComputedTable, CoreEntry, DlvCore,
    DlvPolicyFulfillmentBody, EntryKind, EquivocationProof, EscrowBranch, EscrowOutcome,
    EscrowSigner, EscrowTerms, EscrowVerdict, FrontierRelationship, MatchSide, MatchStart,
    OutcomeTable, OwnerAuthority, OwnerBaselineAuthV1, ParentClaimRef, PrecommitLeg,
    PreEClosureIndex, RouteDigestPreimage, RouteLegEntry, RouteLegSet, SettlementBody,
    SettlementPreimage, SideSignature, SignedHead, SignedSofiObject, SignedSofiResolutionClaim,
    SofiExercise, SofiResolutionClaim, SofiSetupBody, StartBody, SwapHop, TraderCore,
    TraderFulfillmentBody, TraderPreBalance, TraderPrecommitBody, TraderRelationshipLeaf,
    TranscriptEntry, TranscriptOutcome, ValidationRef, VaultCreation, VaultFrontierV1,
    VaultFrontierWitnessV1, VaultGenesisPreimage, VaultHistoryHeadV1, VaultRelationshipLeaf,
    VaultStateLeaf, VerdictSignature, COMPUTED_LABELS, SCHEMA_V1, VAULT_STATUS_ACTIVE,
};
use crate::types::device_state::OfflineBoundaryKind;

type D32 = [u8; 32];

/// What production does with a class's bytes.
enum Read {
    /// The class's own parser, returning the re-encoding of what it parsed.
    Parsed(fn(&[u8]) -> Result<Vec<u8>, String>),
    /// Parsed only inside this enclosing class.
    Nested(u16),
    /// Never parsed: the digest production takes, and the domain hash of the
    /// entry's bytes under that digest's tag and framing.
    Hashed { taken: D32, over_bytes: D32 },
}

struct Shown {
    class: u16,
    schema: u16,
    bytes: Vec<u8>,
    read: Read,
}

const ALG: u16 = sigalg::SPHINCS_PLUS_SPX256F;

fn b(x: u8) -> D32 {
    [x; 32]
}

fn key() -> Vec<u8> {
    vec![0x6B; 64]
}

fn signature() -> Vec<u8> {
    vec![0x5A; 96]
}

fn path() -> Vec<D32> {
    (0..256u32).map(|i| b((i % 251) as u8)).collect()
}

fn ok<T, E: core::fmt::Debug>(r: Result<T, E>, what: &str) -> T {
    match r {
        Ok(v) => v,
        Err(e) => panic!("the {what} fixture does not build: {e:?}"),
    }
}

fn re<E: core::fmt::Debug>(r: Result<Vec<u8>, E>) -> Result<Vec<u8>, String> {
    r.map_err(|e| format!("{e:?}"))
}

fn text(e: DecodeError) -> String {
    format!("{e:?}")
}

/// `bytes` read whole by a nested-object parser.
fn whole<T>(bytes: &[u8], at: fn(&mut Cursor<'_>) -> Result<T, DecodeError>) -> Result<T, String> {
    let mut c = Cursor { b: bytes, i: 0 };
    let value = at(&mut c).map_err(text)?;
    if c.i != bytes.len() {
        return Err(format!("{} trailing bytes", bytes.len() - c.i));
    }
    Ok(value)
}

fn h(tag: TaggedHashDomain<'static>, parts: &[&[u8]]) -> D32 {
    let mut hasher = dsm_domain_hasher(tag);
    for p in parts {
        hasher.update(p);
    }
    *hasher.finalize().as_bytes()
}

fn shown(class: u16, schema: u16, bytes: Vec<u8>, read: Read) -> Shown {
    Shown {
        class,
        schema,
        bytes,
        read,
    }
}

fn leaf_state(b: &[u8]) -> Result<Vec<u8>, String> {
    re(decode_leaf_state(b).map_err(text)?.encode())
}

fn credit_source(b: &[u8]) -> Result<Vec<u8>, String> {
    re(decode_credit_source(b).map_err(text)?.encode())
}

fn validation_ref(b: &[u8]) -> Result<Vec<u8>, String> {
    Ok(whole(b, ValidationRef::at)?.encode())
}

fn core_entry(b: &[u8]) -> Result<Vec<u8>, String> {
    re(whole(b, CoreEntry::at)?.encode())
}

fn settlement(b: &[u8]) -> Result<Vec<u8>, String> {
    re(whole(b, SettlementBody::at)?.encode())
}

fn owner_authority(b: &[u8]) -> Result<Vec<u8>, String> {
    Ok(whole(b, OwnerAuthority::at)?.encode())
}

fn parent_claim_ref(b: &[u8]) -> Result<Vec<u8>, String> {
    Ok(ParentClaimRef::decode(b).map_err(text)?.encode())
}

fn route_digest_shown(class: u16, preimage: &RouteDigestPreimage) -> Shown {
    let bytes = ok(preimage.encode(), "route digest preimage");
    let taken = ok(route_digest(preimage), "route digest");
    let over_bytes = h(TAG_DSM_SOFI_ROUTE_DIGEST, &[&bytes]);
    shown(class, SCHEMA_V1, bytes, Read::Hashed { taken, over_bytes })
}

fn vault_state_leaf() -> VaultStateLeaf {
    VaultStateLeaf {
        owner_genesis: b(0x01),
        owner_device_id: b(0x02),
        create_position: 4,
        market_policy: b(0x0C),
        fee_policy: b(0x0D),
        release_policy: b(0x0E),
        storage_set_id: b(0x0F),
        generation: 3,
        reserve_a: 1_000,
        reserve_b: 2_000,
        status: VAULT_STATUS_ACTIVE,
    }
}

fn hop(vault: u8) -> SwapHop {
    SwapHop {
        vault_id: b(vault),
        parent_root: b(vault ^ 0x0F),
        setup_ref: b(vault ^ 0xF0),
        token_in: b(0x0A),
        amount_in: 100,
        token_out: b(0x0B),
        amount_out: 90,
    }
}

fn mutation_entry(k: u8) -> CoreEntry {
    CoreEntry::Mutation {
        key: b(k),
        pre: b(0x41),
        post: b(0x42),
        path: path(),
    }
}

fn read_entry(k: u8) -> CoreEntry {
    CoreEntry::Read {
        key: b(k),
        value: b(0x93),
        path: path(),
    }
}

fn relationship_entry(vault: u8) -> CoreEntry {
    CoreEntry::Relationship {
        genesis: b(0x11),
        device_id: b(0x12),
        vault_id: b(vault),
        base: b(0x95),
        path: path(),
    }
}

fn closure() -> PreEClosureIndex {
    ok(
        PreEClosureIndex::new(vec![ValidationRef::Setup { setup_ref: b(0x16) }]),
        "closure index",
    )
}

fn trader_core() -> TraderCore {
    ok(
        TraderCore::new(b(0x11), b(0x12), 2, b(0x17), vec![mutation_entry(0x71)]),
        "trader core",
    )
}

fn dlv_core(vault: u8) -> DlvCore {
    // A core's entries are strictly ascending by the key each is about.
    let mut entries = vec![relationship_entry(vault), mutation_entry(vault)];
    entries.sort_by_key(CoreEntry::key);
    ok(
        DlvCore::new(
            b(vault),
            b(vault ^ 0x0F),
            b(0x11),
            b(0x12),
            b(0x95),
            entries,
        ),
        "dlv core",
    )
}

fn swap() -> SettlementBody {
    let cores = [dlv_core(0x31), dlv_core(0x32)];
    SettlementBody::Swap {
        token_in: b(0x0A),
        amount_in: 100,
        token_out: b(0x0B),
        exact_out: 80,
        hops: vec![hop(0x31), hop(0x32)],
        trader_core: trader_core_digest(&ok(trader_core().encode(), "trader core bytes")),
        dlv_cores: cores
            .iter()
            .map(|c| dlv_core_digest(&ok(c.encode(), "dlv core bytes")))
            .collect(),
        closure: closure(),
    }
}

fn precommit() -> TraderPrecommitBody {
    ok(
        TraderPrecommitBody::new(
            b(0x11),
            b(0x12),
            2,
            ParentClaimRef::SingleRoot { claim_ref: b(0x15) },
            b(0xEE),
            vec![
                PrecommitLeg {
                    vault_id: b(0x31),
                    parent_root: b(0x3E),
                    setup_ref: b(0xC1),
                },
                PrecommitLeg {
                    vault_id: b(0x32),
                    parent_root: b(0x3D),
                    setup_ref: b(0xC2),
                },
            ],
            b(0xC4),
            b(0xC5),
            b(0xC6),
            ALG,
            &key(),
        ),
        "precommit",
    )
}

fn fulfillment(p: &TraderPrecommitBody) -> TraderFulfillmentBody {
    ok(
        TraderFulfillmentBody::new(
            precommit_id(p),
            vec![b(0x61), b(0x62)],
            vec![
                AttemptEntry {
                    vault_id: b(0x31),
                    attempt: 0,
                },
                AttemptEntry {
                    vault_id: b(0x32),
                    attempt: 3,
                },
            ],
            3,
            ALG,
            &key(),
            b(0xA7),
        ),
        "fulfillment",
    )
}

fn resolution_claim() -> SofiResolutionClaim {
    SofiResolutionClaim {
        genesis: b(0x11),
        device_id: b(0x12),
        position: 3,
        fulfillment_id: b(0x63),
        realize_root: b(0xC4),
        void_root: b(0xC5),
    }
}

fn signer(k: u8) -> EscrowSigner {
    ok(EscrowSigner::new(ALG, &[k; 64]), "escrow signer")
}

fn computed_table() -> ComputedTable {
    ok(
        ComputedTable::new(b(0xD1), b(0xD2), signer(0xA1), signer(0xB1)),
        "computed table",
    )
}

fn boundary(kind: OfflineBoundaryKind) -> OfflineBoundaryBody {
    let encoded = |x: u8| EncodedPath {
        explicit_heights: [0x80; 32],
        siblings: vec![x; 32],
    };
    OfflineBoundaryBody {
        kind,
        bundle: b(0xB1),
        asset: b(0x0A),
        amount: 25,
        pre_device_root: b(0xB2),
        pre_account_root: b(0xB3),
        pre_allocation: Some(40),
        pre_funding_chain: Some(b(0xB4)),
        account_paths: vec![encoded(0xB5), encoded(0xB6)],
        device_path: encoded(0xB7),
    }
}

/// One object of every live class, through the production encoder.
fn every_class() -> Vec<Shown> {
    let mut all = Vec::new();

    // ── CCB state family ────────────────────────────────────────────────
    let market = ok(
        MarketPolicy::beta_constant_product(b(0x0A), b(0x0B)),
        "market policy",
    );
    let release = ReleasePolicy::beta_owner_local_full_close();
    let fee = ok(FeePolicy::new(30), "fee policy");
    let claim = EncumbranceClaim {
        parent_binding: b(0x21),
        claim_seq: 1,
        amount: 10,
        token: b(0x0A),
        purpose: 1,
    };
    let encumbrances = ok(EncumbranceSet::new(vec![claim.clone()]), "encumbrance set");
    let storage = ok(
        StorageSetMembers::new(&[(&b"node-a"[..], b(0x31)), (&b"node-b"[..], b(0x32))]),
        "storage set",
    );
    let state = VaultStateV2 {
        owner_genesis_id: b(0x01),
        owner_device_id: b(0x02),
        vault_id: b(0x03),
        generation: 4,
        reserve_a: 5,
        reserve_b: 6,
        market_policy: market.clone(),
        release_policy: release.clone(),
        fee_policy: fee,
        encumbrances: encumbrances.clone(),
        iteration_budget: Some(7),
        parent_state_commitment: b(0x08),
        owner_authority_transition_digest: b(0x09),
        storage_set: storage.clone(),
        quorum: 2,
    };
    all.push(shown(
        class::VAULT_STATE_V2,
        VaultStateV2::SCHEMA,
        ok(state.encode(), "vault state"),
        Read::Parsed(|b| re(decode_vault_state(b).map_err(text)?.encode())),
    ));
    all.push(shown(
        class::STORAGE_SET,
        StorageSetMembers::SCHEMA,
        ok(storage.encode(), "storage set bytes"),
        Read::Nested(class::VAULT_STATE_V2),
    ));
    all.push(shown(
        class::ENCUMBRANCE_CLAIM,
        EncumbranceClaim::SCHEMA,
        claim.encode(),
        Read::Nested(class::VAULT_STATE_V2),
    ));
    all.push(shown(
        class::ENCUMBRANCE_SET,
        EncumbranceSet::SCHEMA,
        ok(encumbrances.encode(), "encumbrance set bytes"),
        Read::Nested(class::VAULT_STATE_V2),
    ));
    all.push(shown(
        class::MARKET_POLICY,
        MarketPolicy::SCHEMA,
        market.encode(),
        Read::Parsed(|b| Ok(decode_market_policy(b).map_err(text)?.encode())),
    ));
    all.push(shown(
        class::RELEASE_POLICY,
        ReleasePolicy::SCHEMA,
        release.encode(),
        Read::Parsed(|b| Ok(decode_release_policy(b).map_err(text)?.encode())),
    ));
    all.push(shown(
        class::FEE_POLICY,
        FeePolicy::SCHEMA,
        fee.encode(),
        Read::Parsed(|b| Ok(decode_fee_policy(b).map_err(text)?.encode())),
    ));
    let genesis = ok(
        GenesisParamsV3::new(b(0x41), b"dsm-testnet", 3, ALG, &key()),
        "genesis params",
    );
    all.push(shown(
        class::GENESIS_PARAMS_V3,
        GenesisParamsV3::SCHEMA,
        ok(genesis.encode(), "genesis params bytes"),
        Read::Parsed(|b| re(decode_genesis_params(b).map_err(text)?.encode())),
    ));
    let delegation = RootProgressionDelegation {
        genesis_id: b(0x42),
        role: role::DEVICE_TREE_ROOT_PROGRESSION,
        role_version: role::BETA_ROLE_VERSION,
        delegated_alg_id: ALG,
        delegated_pk: key(),
        delegation_number: 1,
        parent_delegation_digest: b(0x43),
        activation_transition_digest: b(0x44),
    };
    all.push(shown(
        class::ROOT_PROGRESSION_DELEGATION,
        RootProgressionDelegation::SCHEMA,
        ok(delegation.encode(), "delegation"),
        Read::Parsed(|b| re(decode_delegation(b).map_err(text)?.encode())),
    ));
    let transition = DeviceTreeRootTransition {
        genesis_id: b(0x42),
        predecessor_transition_digest: b(0x45),
        new_root: b(0x46),
        version_number: 2,
        delegation_digest: b(0x47),
    };
    all.push(shown(
        class::DEVICE_TREE_ROOT_TRANSITION,
        DeviceTreeRootTransition::SCHEMA,
        transition.encode(),
        Read::Parsed(|b| Ok(decode_transition(b).map_err(text)?.encode())),
    ));

    // ── economic family ─────────────────────────────────────────────────
    let root_claim = ok(
        EconomicRootClaimBody::new(
            b(0x51),
            b(0x52),
            3,
            b(0x53),
            b(0x54),
            b(0x55),
            ALG,
            &key(),
            b(0x56),
        ),
        "economic root claim",
    );
    all.push(shown(
        class::ECONOMIC_ROOT_CLAIM_BODY,
        EconomicRootClaimBody::SCHEMA,
        ok(root_claim.encode(), "economic root claim bytes"),
        Read::Parsed(|b| re(decode_economic_root_claim_body(b).map_err(text)?.encode())),
    ));
    let manifest = ok(
        EconomicAdmissionManifest::new(
            b(0x57),
            b(0x58),
            b(0x59),
            AdmissionSubstrate::DsmSuccessor {
                evidence_addr: b(0x5A),
            },
            vec![b(0x5B), b(0x5C)],
        ),
        "admission manifest",
    );
    all.push(shown(
        class::ECONOMIC_ADMISSION_MANIFEST,
        EconomicAdmissionManifest::SCHEMA,
        ok(manifest.encode(), "admission manifest bytes"),
        Read::Parsed(|b| re(decode_admission_manifest(b).map_err(text)?.encode())),
    ));
    let before = EconomicLeafState::Balance(ok(
        EconomicBalanceState::new(b(0x0A), 100),
        "balance before",
    ));
    let after =
        EconomicLeafState::Balance(ok(EconomicBalanceState::new(b(0x0A), 150), "balance after"));
    let leaves = [
        (
            class::ECONOMIC_BALANCE_STATE,
            EconomicBalanceState::SCHEMA,
            before.clone(),
        ),
        (
            class::ECONOMIC_CONSUMED_SOURCE_STATE,
            EconomicConsumedSourceState::SCHEMA,
            EconomicLeafState::ConsumedSource(EconomicConsumedSourceState {
                source_id: b(0x61),
                consumer_economic_operation_id: b(0x62),
            }),
        ),
        (
            class::ECONOMIC_TOKEN_CREATION_STATE,
            EconomicTokenCreationState::SCHEMA,
            EconomicLeafState::TokenCreation(EconomicTokenCreationState {
                policy_commit: b(0x0A),
            }),
        ),
        (
            class::SOFI_TRADER_RELATIONSHIP_LEAF,
            SCHEMA_V1,
            EconomicLeafState::Relationship(TraderRelationshipLeaf {
                vault_id: b(0x03),
                leaf: b(0x63),
            }),
        ),
        (
            class::SOFI_VAULT_CREATION,
            SCHEMA_V1,
            EconomicLeafState::VaultCreation(VaultCreation {
                vault_id: b(0x03),
                genesis_root: b(0x64),
                amount_a: 10,
                amount_b: 20,
            }),
        ),
    ];
    for (leaf_class, schema, leaf) in leaves {
        all.push(shown(
            leaf_class,
            schema,
            ok(leaf.encode(), "economic leaf"),
            Read::Parsed(leaf_state),
        ));
    }
    let mutation = ok(
        EconomicLeafMutation::new(Some(before), Some(after), path()),
        "leaf mutation",
    );
    all.push(shown(
        class::ECONOMIC_LEAF_MUTATION,
        EconomicLeafMutation::SCHEMA,
        ok(mutation.encode(), "leaf mutation bytes"),
        Read::Parsed(|b| re(decode_leaf_mutation(b).map_err(text)?.encode())),
    ));
    let release_source = CreditSource::GenesisRelease(CreditSourceGenesisRelease {
        credit_mutation_index: 0,
    });
    let witness = ok(
        EconomicTransitionWitness::new(
            b(0x71),
            b(0x72),
            b(0x73),
            b(0x74),
            vec![mutation],
            vec![release_source.clone()],
        ),
        "transition witness",
    );
    all.push(shown(
        class::ECONOMIC_TRANSITION_WITNESS,
        EconomicTransitionWitness::SCHEMA,
        ok(witness.encode(), "transition witness bytes"),
        Read::Parsed(|b| re(decode_transition_witness(b).map_err(text)?.encode())),
    ));
    let sources = [
        (
            class::CREDIT_SOURCE_VALIDATED_PEER_DEBIT,
            CreditSourceValidatedPeerDebit::SCHEMA,
            CreditSource::ValidatedPeerDebit(CreditSourceValidatedPeerDebit {
                credit_mutation_index: 0,
                peer_genesis: b(0x81),
                peer_devid: b(0x82),
                peer_economic_position: 9,
                peer_debit_mutation_index: 1,
                acceptance_evidence_addr: b(0x83),
            }),
        ),
        (
            class::CREDIT_SOURCE_NATIVE_RESERVE_RELEASE,
            CreditSourceNativeReserveRelease::SCHEMA,
            CreditSource::NativeReserveRelease(CreditSourceNativeReserveRelease {
                credit_mutation_index: 0,
                reserve_id: b(0x84),
                generation: 5,
                release_evidence_addr: b(0x85),
            }),
        ),
        (
            class::CREDIT_SOURCE_GENESIS_RELEASE,
            CreditSourceGenesisRelease::SCHEMA,
            release_source,
        ),
        (
            class::CREDIT_SOURCE_OFFLINE_BOUNDARY_DEBIT,
            CreditSourceOfflineBoundaryDebit::SCHEMA,
            CreditSource::OfflineBoundaryDebit(CreditSourceOfflineBoundaryDebit {
                credit_mutation_index: 0,
            }),
        ),
    ];
    for (source_class, schema, source) in sources {
        all.push(shown(
            source_class,
            schema,
            ok(source.encode(), "credit source"),
            Read::Parsed(credit_source),
        ));
    }
    for (boundary_class, kind) in [
        (class::OFFLINE_LOAD_BOUNDARY_BODY, OfflineBoundaryKind::Load),
        (
            class::OFFLINE_UNLOAD_BOUNDARY_BODY,
            OfflineBoundaryKind::Unload,
        ),
    ] {
        all.push(shown(
            boundary_class,
            1,
            ok(boundary(kind).encode(), "offline boundary"),
            Read::Parsed(|b| re(OfflineBoundaryBody::decode(b).map_err(text)?.encode())),
        ));
    }

    // ── SoFi family ─────────────────────────────────────────────────────
    let setup = ok(
        SofiSetupBody::new(b(0x11), b(0x12), 1, b(0x31), b(0x13), b(0x14), ALG, &key()),
        "setup",
    );
    all.push(shown(
        class::SOFI_SETUP_BODY,
        SCHEMA_V1,
        setup.encode(),
        Read::Parsed(|b| Ok(SofiSetupBody::decode(b).map_err(text)?.encode())),
    ));
    let p = precommit();
    all.push(shown(
        class::SOFI_TRADER_PRECOMMIT_BODY,
        SCHEMA_V1,
        p.encode(),
        Read::Parsed(|b| Ok(TraderPrecommitBody::decode(b).map_err(text)?.encode())),
    ));
    let policy_fulfillment = DlvPolicyFulfillmentBody {
        precommit_id: precommit_id(&p),
        external_commitment: b(0xEE),
        vault_id: b(0x31),
        parent_root: b(0x3E),
        shadow_core: b(0x65),
    };
    all.push(shown(
        class::SOFI_DLV_POLICY_FULFILLMENT_BODY,
        SCHEMA_V1,
        policy_fulfillment.encode(),
        Read::Parsed(|b| Ok(DlvPolicyFulfillmentBody::decode(b).map_err(text)?.encode())),
    ));
    let f = fulfillment(&p);
    all.push(shown(
        class::SOFI_TRADER_FULFILLMENT_BODY,
        SCHEMA_V1,
        f.encode(),
        Read::Parsed(|b| Ok(TraderFulfillmentBody::decode(b).map_err(text)?.encode())),
    ));
    let c = resolution_claim();
    let c_bytes = c.encode();
    let key_len = (key().len() as u32).to_be_bytes();
    all.push(shown(
        class::SOFI_RESOLUTION_CLAIM,
        SCHEMA_V1,
        c_bytes.clone(),
        Read::Hashed {
            taken: resolution_claim_signing_digest(&c, ALG, &key(), &b(0xA7)),
            over_bytes: h(
                TAG_DSM_SOFI_RESOLUTION_CLAIM_SIGN,
                &[&c_bytes, &ALG.to_be_bytes(), &key_len, &key(), &b(0xA7)],
            ),
        },
    ));
    all.push(shown(
        class::SOFI_PARENT_SINGLE_ROOT_CLAIM,
        SCHEMA_V1,
        ParentClaimRef::SingleRoot { claim_ref: b(0x15) }.encode(),
        Read::Parsed(parent_claim_ref),
    ));
    all.push(shown(
        class::SOFI_PARENT_CONDITIONAL_CLAIM,
        SCHEMA_V1,
        ParentClaimRef::Conditional {
            fulfillment_id: b(0x63),
        }
        .encode(),
        Read::Parsed(parent_claim_ref),
    ));
    for (ref_class, reference) in [
        (
            class::SOFI_REF_CONTENT_ADDR,
            ValidationRef::ContentAddr {
                object_class: class::MARKET_POLICY,
                addr: b(0x66),
            },
        ),
        (
            class::SOFI_REF_SINGLE_ROOT_CLAIM,
            ValidationRef::SingleRootClaim { claim_ref: b(0x15) },
        ),
        (
            class::SOFI_REF_CONDITIONAL_CLAIM,
            ValidationRef::ConditionalClaim {
                genesis: b(0x11),
                device_id: b(0x12),
                position: 3,
                fulfillment_id: b(0x63),
            },
        ),
        (
            class::SOFI_REF_SETUP,
            ValidationRef::Setup { setup_ref: b(0x16) },
        ),
    ] {
        all.push(shown(
            ref_class,
            SCHEMA_V1,
            reference.encode(),
            Read::Parsed(validation_ref),
        ));
    }
    all.push(shown(
        class::SOFI_PRE_E_CLOSURE_INDEX,
        SCHEMA_V1,
        closure().encode(),
        Read::Parsed(|b| Ok(whole(b, PreEClosureIndex::at)?.encode())),
    ));
    let gamma = ok(
        RouteLegSet::new(vec![
            RouteLegEntry {
                vault_id: b(0x31),
                parent_root: b(0x3E),
                setup_ref: b(0xC1),
                shadow_core: b(0x65),
            },
            RouteLegEntry {
                vault_id: b(0x32),
                parent_root: b(0x3D),
                setup_ref: b(0xC2),
                shadow_core: b(0x67),
            },
        ]),
        "route leg set",
    );
    let gamma_bytes = gamma.encode();
    all.push(shown(
        class::SOFI_ROUTE_LEG_SET,
        SCHEMA_V1,
        gamma_bytes.clone(),
        Read::Hashed {
            taken: route_leg_set_digest(&gamma),
            over_bytes: h(TAG_DSM_SOFI_ROUTE_LEG_SET, &[&gamma_bytes]),
        },
    ));
    all.push(shown(
        class::SOFI_VAULT_STATE_LEAF,
        SCHEMA_V1,
        ok(vault_state_leaf().encode(), "vault state leaf"),
        Read::Parsed(|b| re(VaultStateLeaf::decode(b).map_err(text)?.encode())),
    ));
    let relationship = VaultRelationshipLeaf {
        trader_genesis: b(0x11),
        trader_device_id: b(0x12),
        leaf: b(0x68),
    };
    all.push(shown(
        class::SOFI_VAULT_RELATIONSHIP_LEAF,
        SCHEMA_V1,
        relationship.encode(),
        Read::Parsed(|b| Ok(VaultRelationshipLeaf::decode(b).map_err(text)?.encode())),
    ));
    for (entry_class, entry) in [
        (class::SOFI_CORE_ENTRY_MUTATION, mutation_entry(0x71)),
        (class::SOFI_CORE_ENTRY_READ, read_entry(0x72)),
        (
            class::SOFI_CORE_ENTRY_RELATIONSHIP,
            relationship_entry(0x31),
        ),
    ] {
        all.push(shown(
            entry_class,
            SCHEMA_V1,
            ok(entry.encode(), "core entry"),
            Read::Parsed(core_entry),
        ));
    }
    all.push(shown(
        class::SOFI_TRADER_CORE,
        SCHEMA_V1,
        ok(trader_core().encode(), "trader core bytes"),
        Read::Parsed(|b| re(whole(b, TraderCore::at)?.encode())),
    ));
    all.push(shown(
        class::SOFI_DLV_CORE,
        SCHEMA_V1,
        ok(dlv_core(0x31).encode(), "dlv core bytes"),
        Read::Parsed(|b| re(whole(b, DlvCore::at)?.encode())),
    ));
    let close = SettlementBody::Close {
        vault_id: b(0x31),
        parent_root: b(0x3E),
        setup_ref: b(0xC1),
        owner_authority: OwnerAuthority::Origin,
        reserve_a: 0,
        reserve_b: 0,
        trader_core: b(0x69),
        dlv_core: b(0x6A),
        closure: closure(),
    };
    let release_body = SettlementBody::Release {
        vault_id: b(0x31),
        parent_root: b(0x3E),
        setup_ref: b(0xC1),
        verdict_cell: b(0x6B),
        outcome: b"win".to_vec(),
        amount: 70,
        trader_core: b(0x69),
        dlv_core: b(0x6A),
        closure: closure(),
    };
    for (body_class, body) in [
        (class::SOFI_SETTLEMENT_SWAP, swap()),
        (class::SOFI_SETTLEMENT_CLOSE, close.clone()),
        (class::SOFI_SETTLEMENT_RELEASE, release_body.clone()),
    ] {
        all.push(shown(
            body_class,
            SCHEMA_V1,
            ok(body.encode(), "settlement body"),
            Read::Parsed(settlement),
        ));
    }
    for (authority_class, authority) in [
        (class::SOFI_OWNER_AUTHORITY_ORIGIN, OwnerAuthority::Origin),
        (
            class::SOFI_OWNER_AUTHORITY_DSM_SUCCESSOR,
            OwnerAuthority::DsmSuccessor {
                authority_class: class::DEVICE_TREE_ROOT_TRANSITION,
                authority_addr: b(0x6C),
            },
        ),
    ] {
        all.push(shown(
            authority_class,
            SCHEMA_V1,
            authority.encode(),
            Read::Parsed(owner_authority),
        ));
    }
    all.push(route_digest_shown(
        class::SOFI_ROUTE_DIGEST_SWAP,
        &swap().route_digest_preimage(),
    ));
    all.push(route_digest_shown(
        class::SOFI_ROUTE_DIGEST_CLOSE,
        &close.route_digest_preimage(),
    ));
    all.push(route_digest_shown(
        class::SOFI_ROUTE_DIGEST_RELEASE,
        &release_body.route_digest_preimage(),
    ));
    let preimage = ok(
        SettlementPreimage::new(swap(), trader_core(), vec![dlv_core(0x31), dlv_core(0x32)]),
        "settlement preimage",
    );
    let preimage_bytes = ok(preimage.encode(), "settlement preimage bytes");
    all.push(shown(
        class::SOFI_SETTLEMENT_PREIMAGE,
        SCHEMA_V1,
        preimage_bytes.clone(),
        Read::Parsed(|b| re(SettlementPreimage::decode(b).map_err(text)?.encode())),
    ));
    let genesis_preimage = VaultGenesisPreimage {
        owner_genesis: b(0x01),
        owner_device_id: b(0x02),
        create_position: 4,
        state: vault_state_leaf(),
    };
    all.push(shown(
        class::SOFI_VAULT_GENESIS_PREIMAGE,
        SCHEMA_V1,
        ok(genesis_preimage.encode(), "vault genesis preimage"),
        Read::Parsed(|b| re(VaultGenesisPreimage::decode(b).map_err(text)?.encode())),
    ));
    let signed = ok(
        SignedSofiObject::new(
            class::SOFI_TRADER_PRECOMMIT_BODY,
            &p.encode(),
            ALG,
            &signature(),
        ),
        "signed object",
    );
    all.push(shown(
        class::SOFI_SIGNED_OBJECT,
        SCHEMA_V1,
        signed.encode(),
        Read::Parsed(|b| Ok(SignedSofiObject::decode(b).map_err(text)?.encode())),
    ));
    let exercise = ok(
        SofiExercise::new(
            f.encode(),
            c_bytes.clone(),
            p.encode(),
            preimage_bytes,
            vec![policy_fulfillment.encode()],
            vec![],
        ),
        "exercise",
    );
    all.push(shown(
        class::SOFI_EXERCISE,
        SCHEMA_V1,
        exercise.encode(),
        Read::Parsed(|b| Ok(SofiExercise::decode(b).map_err(text)?.encode())),
    ));
    let pre_balance = ok(
        TraderPreBalance::new(b(0x11), b(0x12), b(0x0A), 100),
        "trader pre-balance",
    );
    all.push(shown(
        class::SOFI_TRADER_PRE_BALANCE,
        SCHEMA_V1,
        pre_balance.encode(),
        Read::Parsed(|b| Ok(TraderPreBalance::decode(b).map_err(text)?.encode())),
    ));
    let signed_claim = ok(
        SignedSofiResolutionClaim::new(c, ALG, &key(), b(0xA7), &signature()),
        "signed resolution claim",
    );
    all.push(shown(
        class::SOFI_SIGNED_RESOLUTION_CLAIM,
        SCHEMA_V1,
        signed_claim.encode(),
        Read::Parsed(|b| Ok(SignedSofiResolutionClaim::decode(b).map_err(text)?.encode())),
    ));

    // ── escrow family ───────────────────────────────────────────────────
    let decided = ok(
        EscrowOutcome::new(b"win", vec![signer(0xA1)]),
        "escrow outcome",
    );
    let lost = ok(
        EscrowOutcome::new(b"lose", vec![signer(0xA1)]),
        "escrow outcome",
    );
    let terms = ok(
        EscrowTerms::new(
            b(0x0A),
            b(0xEE),
            // Branches are strictly ascending by outcome: "lose" < "win".
            vec![
                EscrowBranch::new(lost.clone(), b(0x21), b(0x22)),
                EscrowBranch::new(decided.clone(), b(0x11), b(0x12)),
            ],
        ),
        "escrow terms",
    );
    all.push(shown(
        class::ESCROW_TERMS,
        SCHEMA_V1,
        terms.encode(),
        Read::Parsed(|b| Ok(EscrowTerms::decode(b).map_err(text)?.encode())),
    ));
    let verdict = ok(
        EscrowVerdict::new(
            b(0xEE),
            ok(OutcomeTable::new(vec![lost, decided]), "outcome table"),
            b"win",
            vec![ok(
                VerdictSignature::new(signer(0xA1), &signature()),
                "verdict signature",
            )],
        ),
        "escrow verdict",
    );
    all.push(shown(
        class::ESCROW_VERDICT,
        SCHEMA_V1,
        verdict.encode(),
        Read::Parsed(|b| Ok(EscrowVerdict::decode(b).map_err(text)?.encode())),
    ));
    let computed = ok(
        ComputedEscrowTerms::new(
            b(0x0A),
            b(0xEE),
            computed_table(),
            COMPUTED_LABELS
                .iter()
                .zip([0x11u8, 0x21, 0x31])
                .map(|(label, who)| ComputedBranch::new(label, b(who), b(who + 1)))
                .collect(),
        ),
        "computed escrow terms",
    );
    all.push(shown(
        class::ESCROW_COMPUTED_TERMS,
        SCHEMA_V1,
        computed.encode(),
        Read::Parsed(|b| Ok(ComputedEscrowTerms::decode(b).map_err(text)?.encode())),
    ));
    let entry = ok(
        TranscriptEntry::new(
            1,
            MatchSide::A,
            EntryKind::Commit {
                commitment: b(0xD3),
            },
        ),
        "transcript entry",
    );
    all.push(shown(
        class::ESCROW_TRANSCRIPT_ENTRY,
        SCHEMA_V1,
        entry.encode(),
        Read::Parsed(|b| Ok(TranscriptEntry::decode(b).map_err(text)?.encode())),
    ));
    let outcome = ok(
        TranscriptOutcome::new(
            b(0xEE),
            computed_table(),
            b"setup",
            vec![entry.encode()],
            vec![
                ok(
                    SideSignature::new(MatchSide::A, &signature()),
                    "side signature",
                ),
                ok(
                    SideSignature::new(MatchSide::B, &signature()),
                    "side signature",
                ),
            ],
        ),
        "transcript outcome",
    );
    all.push(shown(
        class::ESCROW_TRANSCRIPT_OUTCOME,
        SCHEMA_V1,
        outcome.encode(),
        Read::Parsed(|b| Ok(TranscriptOutcome::decode(b).map_err(text)?.encode())),
    ));
    let equivocation = ok(
        EquivocationProof::new(
            b(0xEE),
            computed_table(),
            MatchSide::A,
            1,
            ok(SignedHead::new(b(0xD4), &signature()), "signed head"),
            ok(SignedHead::new(b(0xD5), &signature()), "signed head"),
        ),
        "equivocation proof",
    );
    all.push(shown(
        class::ESCROW_EQUIVOCATION_PROOF,
        SCHEMA_V1,
        equivocation.encode(),
        Read::Parsed(|b| Ok(EquivocationProof::decode(b).map_err(text)?.encode())),
    ));
    let start = ok(
        MatchStart::new(
            b(0xEE),
            computed_table(),
            StartBody::Start {
                ready_a: signature(),
                ready_b: signature(),
            },
        ),
        "match start",
    );
    all.push(shown(
        class::ESCROW_MATCH_START,
        SCHEMA_V1,
        start.encode(),
        Read::Parsed(|b| Ok(MatchStart::decode(b).map_err(text)?.encode())),
    ));

    // ── shared lineage family ───────────────────────────────────────────
    all.push(shown(
        class::SHARED_LINEAGE_GENESIS,
        SCHEMA_V1,
        SharedGenesisV1::new(LineageKind::Vault, b(0x31), b(0x91), b(0x92)).encode(),
        Read::Parsed(|b| Ok(SharedGenesisV1::decode(b).map_err(text)?.encode())),
    ));
    all.push(shown(
        class::SHARED_LINEAGE_GENERATION,
        SCHEMA_V1,
        ok(
            SharedGenerationV1::new(LineageKind::Vault, b(0x31), 1, b(0x93), b(0x94), b(0x95)),
            "generation",
        )
        .encode(),
        Read::Parsed(|b| Ok(SharedGenerationV1::decode(b).map_err(text)?.encode())),
    ));
    all.push(shown(
        class::SHARED_LINEAGE_GENERATION_HINT,
        SCHEMA_V1,
        ok(
            GenerationHintV1::new(LineageKind::Vault, b(0x31), 1, b(0x94), b(0x96), b(0x95)),
            "generation hint",
        )
        .encode(),
        Read::Parsed(|b| Ok(GenerationHintV1::decode(b).map_err(text)?.encode())),
    ));
    let roots: Vec<D32> = (0..=EPOCH_GENERATIONS).map(|i| b(0x40 + i as u8)).collect();
    all.push(shown(
        class::SHARED_LINEAGE_CHECKPOINT,
        SCHEMA_V1,
        ok(
            CheckpointV1::new(
                LineageKind::Vault,
                b(0x31),
                0,
                b(0x97),
                b(0x98),
                roots,
                b(0x99),
            ),
            "checkpoint",
        )
        .encode(),
        Read::Parsed(|b| Ok(CheckpointV1::decode(b).map_err(text)?.encode())),
    ));
    let steps: Vec<BundleStep> = (0..EPOCH_GENERATIONS)
        .map(|i| BundleStep::Vault {
            attempt: i,
            external_commitment: b(0xEE),
            trader_genesis: b(0x11),
            trader_device_id: b(0x12),
            trader_position: i + 1,
            siblings: vec![(b(0x32), b(0x3D))],
        })
        .collect();
    all.push(shown(
        class::SHARED_LINEAGE_TRANSITION_BUNDLE,
        SCHEMA_V1,
        ok(
            TransitionBundleV1::new(LineageKind::Vault, b(0x31), 0, steps),
            "transition bundle",
        )
        .encode(),
        Read::Parsed(|b| Ok(TransitionBundleV1::decode(b).map_err(text)?.encode())),
    ));

    // ── frontier family ─────────────────────────────────────────────────
    let frontier = VaultFrontierV1 {
        vault_id: b(0x31),
        generation: 3,
        root: b(0x9A),
        history_root: b(0x9B),
    };
    all.push(shown(
        class::SOFI_VAULT_FRONTIER,
        SCHEMA_V1,
        frontier.encode(),
        Read::Parsed(|b| Ok(VaultFrontierV1::decode(b).map_err(text)?.encode())),
    ));
    let frontier_witness = VaultFrontierWitnessV1 {
        state_leaf: vault_state_leaf(),
        state_path: path(),
        relationship: FrontierRelationship::Present {
            leaf: relationship,
            path: path(),
        },
    };
    all.push(shown(
        class::SOFI_VAULT_FRONTIER_WITNESS,
        SCHEMA_V1,
        ok(frontier_witness.encode(), "frontier witness"),
        Read::Parsed(|b| re(VaultFrontierWitnessV1::decode(b).map_err(text)?.encode())),
    ));
    all.push(shown(
        class::SOFI_OWNER_BASELINE_AUTH,
        SCHEMA_V1,
        OwnerBaselineAuthV1 {
            frontier_commitment: b(0x9C),
            owner_authority_transition_digest: b(0x9D),
        }
        .encode(),
        Read::Parsed(|b| Ok(OwnerBaselineAuthV1::decode(b).map_err(text)?.encode())),
    ));
    // Generation 2 is three leaves, so two peaks.
    let history = VaultHistoryHeadV1 {
        vault_id: b(0x31),
        generation: 2,
        peaks: vec![b(0x9E), b(0x9F)],
    };
    all.push(shown(
        class::SOFI_VAULT_HISTORY_HEAD,
        SCHEMA_V1,
        ok(history.encode(), "history head"),
        Read::Parsed(|b| re(VaultHistoryHeadV1::decode(b).map_err(text)?.encode())),
    ));

    all
}

/// The live classes, read from the `class` module's own source.
fn live_classes() -> BTreeMap<u16, String> {
    let src = include_str!("mod.rs");
    let Some(start) = src.find("pub mod class {") else {
        panic!("the class module is not in ccb/mod.rs");
    };
    let body = &src[start..];
    let Some(end) = body.find("\n}\n") else {
        panic!("the class module does not close");
    };
    let mut live = BTreeMap::new();
    for line in body[..end].lines() {
        let Some(rest) = line.trim().strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, value)) = rest.split_once(": u16 = 0x") else {
            panic!("a class constant that is not a u16 hex literal: {rest}");
        };
        let Ok(number) = u16::from_str_radix(value.trim_end_matches(';'), 16) else {
            panic!("an unreadable class number: {rest}");
        };
        if let Some(previous) = live.insert(number, name.to_string()) {
            panic!("class {number:#06x} is allocated twice: {previous} and {name}");
        }
    }
    live
}

/// Lengths at which a truncation is tried: every length through the first
/// 128 bytes and the last 128, and every 97th between.
fn cuts(len: usize) -> Vec<usize> {
    let mut at: Vec<usize> = (0..len.min(128)).collect();
    at.extend((128..len.saturating_sub(128)).step_by(97));
    at.extend(len.saturating_sub(128).max(128)..len);
    at
}

#[test]
fn every_live_class_has_one_encoding_its_parser_reads_back_exactly() {
    let live = live_classes();
    let all = every_class();
    let mut by_class: BTreeMap<u16, &Shown> = BTreeMap::new();
    for s in &all {
        let Some(name) = live.get(&s.class) else {
            panic!("{:#06x} has an entry here and is not a live class", s.class);
        };
        if by_class.insert(s.class, s).is_some() {
            panic!("{name} has two entries");
        }
    }
    for (number, name) in &live {
        assert!(
            by_class.contains_key(number),
            "{name} ({number:#06x}) is a live class with no object here: give it its \
             encoder and an entry, or move it out of `class`"
        );
    }

    for s in &all {
        let name = &live[&s.class];
        let mut envelope = s.class.to_be_bytes().to_vec();
        envelope.extend_from_slice(&s.schema.to_be_bytes());
        assert_eq!(
            s.bytes.get(..4),
            Some(envelope.as_slice()),
            "{name}: the encoding does not open with its class and live schema"
        );
        match &s.read {
            Read::Parsed(parse) => {
                assert_eq!(
                    parse(&s.bytes),
                    Ok(s.bytes.clone()),
                    "{name}: the parser does not read back exactly the encoded bytes"
                );
                let mut longer = s.bytes.clone();
                longer.push(0x00);
                if let Ok(read) = parse(&longer) {
                    panic!(
                        "{name}: a trailing byte is accepted, read as {} bytes",
                        read.len()
                    );
                }
                for n in cuts(s.bytes.len()) {
                    if let Ok(read) = parse(&s.bytes[..n]) {
                        panic!(
                            "{name}: the first {n} of {} bytes parse, as {} bytes",
                            s.bytes.len(),
                            read.len()
                        );
                    }
                }
                let mut foreign = s.bytes.clone();
                foreign[..2].copy_from_slice(&burned_class::STORAGE_MEMBER_ID.to_be_bytes());
                if let Ok(read) = parse(&foreign) {
                    panic!(
                        "{name}: the bytes under a burned class parse, as {} bytes",
                        read.len()
                    );
                }
            }
            Read::Nested(outer) => {
                let Some(enclosing) = by_class.get(outer) else {
                    panic!("{name} is nested in {outer:#06x}, which has no entry");
                };
                let Read::Parsed(_) = enclosing.read else {
                    panic!("{name} is nested in {outer:#06x}, which production does not parse");
                };
                assert!(
                    enclosing
                        .bytes
                        .windows(s.bytes.len())
                        .any(|w| w == s.bytes.as_slice()),
                    "{name}: its encoding is not the one inside {}",
                    live[outer]
                );
            }
            Read::Hashed { taken, over_bytes } => {
                assert_eq!(
                    taken, over_bytes,
                    "{name}: the digest production takes is not over these bytes"
                );
            }
        }
    }
}
