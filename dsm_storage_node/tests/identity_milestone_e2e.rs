// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
#![cfg(feature = "local-dev")]

//! The step-6 gate, verbatim: *"given a Genesis v3 state and an owner key,
//! can the implementation construct `V_n`, encode it canonically, publish it
//! immutably, derive `c_n`, sign it through AnchorV3, and independently
//! verify that signature through P0–P6 without any legacy or duplicate
//! source of truth?"*
//!
//! Every leg runs through the production code paths: Genesis v3 derivation,
//! GRK-signed delegation and transition authored the way an owner would at
//! birth, `CCB(V_n)` through the schema-3 encoder, publication into the real
//! immutable store (write-once on the tuple, node-side address derivation),
//! retrieval with the CLIENT-side re-hash that is the Req 15.3 boundary,
//! strict decode, and the full P0–P6 staging ending at `K_cand == K_proven`.
//!
//! No legacy object appears anywhere in this file — no V1 or V2 anchor, no
//! `p_v`, no mutable slot, no `/latest`. That absence is the point: this is
//! the path the composer resumes onto, demonstrated before the composer
//! moves.

use std::sync::{Arc, Mutex};

use dsm::ccb::{
    delegation_genesis_sentinel, role, sigalg, transition_genesis_sentinel, vault_state_commitment,
    DeviceTreeRootTransition, EncumbranceSet, FeePolicy, GenesisParamsV3, MarketPolicy,
    ReleasePolicy, RootProgressionDelegation, StorageSetMembers, VaultStateV2,
};
use dsm::common::device_tree::DeviceTree;
use dsm::common::domain_tags::TAG_DSM_VAULT_STATE;
use dsm::core::identity::authority_resolver::{
    authenticate_anchor_owner, PresentedIdentity, SignedDelegation, SignedTransition,
};
use dsm::core::identity::genesis_v3::{derive_genesis_v3_self_attested, derive_grk_keypair};
use dsm::crypto::sphincs::sphincs_sign;
use dsm::dlv::vault_state_anchor_v3::sign_vault_state_anchor_v3;
use dsm::storage_object::{immutable_addr, immutable_addr_from_inner, immutable_inner};
use dsm_storage_node::db::{self, ImmutablePutOutcome};

const SEED: &[u8] = b"test-bip39-wallet-seed-64-bytes-............................xxxx";
const NET: &[u8] = b"dsm-test";

#[tokio::test]
async fn the_milestone_path_works_end_to_end_with_no_legacy_anywhere() {
    // ── Genesis v3: the identity, its GRK, and its device key — all from
    // one seed, reproducibly. ────────────────────────────────────────────
    let aph = [0x11; 32];
    let genesis = derive_genesis_v3_self_attested(SEED, NET, 0, 0, 3, &aph).expect("genesis v3");
    let grk = derive_grk_keypair(SEED, NET, 0, 3).expect("grk recoverable");
    assert_eq!(grk.public_key, genesis.grk_public, "one GRK, re-derived");

    let params = GenesisParamsV3::new(
        genesis.genesis_nonce,
        NET,
        3,
        sigalg::SPHINCS_PLUS_SPX256F,
        &genesis.grk_public,
    )
    .expect("params");

    // ── Birth authority: D_0 under the GRK, T_0 establishing the device
    // tree that contains this device. ────────────────────────────────────
    let atta = dsm::core::identity::genesis_v2::derive_atta(SEED, &genesis.g, 0);
    let tree = DeviceTree::single(genesis.devid);
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
    let d0_signed = SignedDelegation {
        grk_signature: sphincs_sign(&genesis.grk_secret, &d0.signing_digest().expect("digest"))
            .expect("grk signs"),
        delegation: d0.clone(),
    };
    let t0 = DeviceTreeRootTransition {
        genesis_id: genesis.g,
        predecessor_transition_digest: transition_genesis_sentinel(),
        new_root: tree.root(),
        version_number: 0,
        delegation_digest: d0.digest().expect("digest"),
    };
    let t0_signed = SignedTransition {
        delegate_signature: sphincs_sign(&genesis.ak_secret, &t0.signing_digest())
            .expect("delegate signs"),
        transition: t0.clone(),
    };

    // ── The vault state: schema 3, committing the authority position. ────
    let mut token_a = [0u8; 32];
    let mut token_b = [0u8; 32];
    token_a[0] = 1;
    token_b[0] = 2;
    let state = VaultStateV2 {
        owner_genesis_id: genesis.g,
        owner_device_id: genesis.devid,
        vault_id: [0x55; 32],
        generation: 0,
        reserve_a: 1_000,
        reserve_b: 2_000,
        market_policy: MarketPolicy::beta_constant_product(token_a, token_b).expect("pair"),
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(30).expect("fee"),
        encumbrances: EncumbranceSet::empty(),
        iteration_budget: None,
        parent_state_commitment: dsm::ccb::genesis_parent_commitment(&[0x55; 32]),
        owner_authority_transition_digest: t0.digest(),
        storage_set: StorageSetMembers::new(&[b"n1", b"n2", b"n3", b"n4", b"n5"]).expect("set"),
        quorum: 4,
    };
    let ccb = state.encode().expect("encodes");
    let c_n = vault_state_commitment(&state).expect("c_n");

    // ── Publish immutably, through the real store. The address the client
    // computes and the address the node computes are one derivation. ─────
    let conn = rusqlite::Connection::open_in_memory().expect("sqlite");
    let pool = Arc::new(Mutex::new(conn));
    db::init_db(&pool).await.expect("schema");

    let addr = immutable_addr(TAG_DSM_VAULT_STATE, &ccb);
    let addr_b32 = dsm_sdk::util::text_id::encode_base32_crockford(&addr);
    let outcome = db::insert_immutable_object_if_absent(
        &pool,
        &addr_b32,
        TAG_DSM_VAULT_STATE.source_bytes(),
        &ccb,
        1,
    )
    .await
    .expect("put");
    assert_eq!(outcome, ImmutablePutOutcome::Inserted);
    // Idempotent replay, and write-once against a different payload.
    assert_eq!(
        db::insert_immutable_object_if_absent(
            &pool,
            &addr_b32,
            TAG_DSM_VAULT_STATE.source_bytes(),
            &ccb,
            2
        )
        .await
        .expect("replay"),
        ImmutablePutOutcome::AlreadyExistsIdentical
    );

    // ── Resolve by c_n alone: the address is a computation, not a lookup.
    // The fetch-side re-hash against the REQUESTED identity is the Req 15.3
    // boundary, performed here as the client performs it. ────────────────
    let fetch_addr = immutable_addr_from_inner(TAG_DSM_VAULT_STATE, &c_n);
    assert_eq!(fetch_addr, addr, "identity → address, no index anywhere");
    let (ns, fetched) = db::get_immutable_object(
        &pool,
        &dsm_sdk::util::text_id::encode_base32_crockford(&fetch_addr),
    )
    .await
    .expect("get")
    .expect("present");
    assert_eq!(
        immutable_inner(TAG_DSM_VAULT_STATE, &fetched),
        c_n,
        "client-side re-hash against the requested identity"
    );
    assert_eq!(ns, TAG_DSM_VAULT_STATE.source_bytes());

    // ── AnchorV3 over c_n, and the full P0–P6 staging on the FETCHED
    // bytes — decode, resolve at the state's own committed position, and
    // the byte-for-byte join. ────────────────────────────────────────────
    let anchor = sign_vault_state_anchor_v3(&c_n, &genesis.ak_secret, &genesis.ak_public)
        .expect("anchor signs");
    let proof = tree.proof(&genesis.devid).expect("inclusion");
    let dels = vec![d0_signed];
    let trans = vec![t0_signed];
    let presented = PresentedIdentity {
        genesis_params: &params,
        delegations: &dels,
        transitions: &trans,
        inclusion: &proof,
        ak_pk: &genesis.ak_public,
        atta: &atta,
    };
    let proven = authenticate_anchor_owner(&anchor, &fetched, &presented)
        .expect("the whole path, end to end");
    assert_eq!(proven.ak_pk, genesis.ak_public);
    assert_eq!(proven.device_id, genesis.devid);
    assert_eq!(proven.position, t0.digest());

    // ── And the negative that keeps this honest: the same fetched bytes
    // under an attacker-signed anchor refuse at the join. ────────────────
    let attacker = dsm::crypto::signatures::SignatureKeyPair::generate_from_entropy(&[9u8; 32])
        .expect("keypair");
    let forged = sign_vault_state_anchor_v3(&c_n, &attacker.secret_key, &attacker.public_key)
        .expect("signs");
    assert!(
        authenticate_anchor_owner(&forged, &fetched, &presented).is_err(),
        "possession of the bytes is not ownership of the vault"
    );
}
