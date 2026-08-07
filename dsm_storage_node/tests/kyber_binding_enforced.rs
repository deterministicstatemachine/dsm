// SPDX-License-Identifier: MIT OR Apache-2.0

//! The node must VERIFY the ML-KEM identity binding before persisting it.
//!
//! Until this branch it did not. `register_device` checked only length and
//! presence, under a comment asserting that "the cryptographic identity binding
//! is verified client-side against the peer's AK".
//!
//! That client-side verification is PARTIAL, not absent. `dsm_sdk`'s
//! `repair_contact_identity_from_quorum` (handlers/app_router_impl.rs:360) does
//! call `verify_kyber_identity_binding`, and does it correctly — against the
//! QR-established `contact_ak` captured at :318, deliberately before repair
//! overwrites `public_key`. But that is ONE repair path, not the general fetch
//! path, so the node was still persisting bindings that nothing had checked at
//! the time of writing. A device could bind any ML-KEM key to its identity by
//! assertion and the node would store it and serve it.
//!
//! These tests drive the REAL handler against a real (in-memory) database and
//! then read the persisted rows back. They deliberately do not test the
//! standalone verifier: the verifier was already correct, and testing it was
//! exactly the thing that failed to notice nothing called it.
//!
//! No skip path. The pre-existing `device_api::tests` return early unless
//! `DSM_RUN_DB_TESTS=1`, so they are vacuous in CI and could not have caught
//! this.

#![cfg(feature = "local-dev")]
#![allow(clippy::disallowed_methods)]

use axum::body::Bytes;
use axum::Extension;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::proto as pb;
use dsm_sdk::util::text_id;
use dsm_storage_node::{
    api::identity::device_api::register_device,
    db,
    replication::{ReplicationConfig, ReplicationManager},
    AppState,
};
use prost::Message;
use std::sync::Arc;

async fn make_state() -> AppState {
    let pool = db::create_pool(":memory:", true).expect("create_pool");
    db::init_db(&pool).await.expect("init_db");
    let replication_config = ReplicationConfig {
        replication_factor: 3,
        gossip_interval_ticks: 100,
        failure_timeout_ticks: 300,
        gossip_fanout: 3,
        max_concurrent_jobs: 10,
    };
    let replication_manager = Arc::new(
        ReplicationManager::new_for_tests(
            replication_config,
            "test-node".to_string(),
            "http://localhost:8080".to_string(),
        )
        .expect("ReplicationManager::new_for_tests"),
    );
    AppState::new(
        "test-node".to_string(),
        "http://localhost:8080",
        None,
        Arc::new(pool),
        replication_manager,
    )
}

const KYBER_PK_LEN: usize = 1184;

/// The canonical binding digest, rebuilt here independently of the SDK so this
/// suite does not simply echo the implementation it is gating.
fn canonical_binding_digest(device_id: &[u8; 32], genesis: &[u8; 32], kyber_pk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"DSM/kyber-identity-binding");
    h.update(&[0u8]); // the encoder's one delimiter
    h.update(device_id);
    h.update(genesis);
    h.update(kyber_pk);
    *h.finalize().as_bytes()
}

struct Device {
    id: [u8; 32],
    genesis: [u8; 32],
    kyber_pk: Vec<u8>,
    ak: SignatureKeyPair,
}

fn device(seed: u8) -> Device {
    Device {
        id: [seed; 32],
        genesis: [seed.wrapping_add(1); 32],
        kyber_pk: vec![seed.wrapping_add(2); KYBER_PK_LEN],
        ak: SignatureKeyPair::generate_from_entropy(
            format!("DSM/test/kyber-enforce/{seed}").as_bytes(),
        )
        .expect("AK"),
    }
}

fn request(d: &Device, kyber_pk: &[u8], sig: Vec<u8>) -> Bytes {
    let req = pb::RegisterDeviceRequest {
        device_id: d.id.to_vec(),
        pubkey: d.ak.public_key().to_vec(),
        genesis_hash: d.genesis.to_vec(),
        kyber_public_key: kyber_pk.to_vec(),
        kyber_binding_sig: sig,
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).expect("encode");
    Bytes::from(buf)
}

fn valid_sig(d: &Device) -> Vec<u8> {
    let digest = canonical_binding_digest(&d.id, &d.genesis, &d.kyber_pk);
    d.ak.sign(&digest).expect("sign binding")
}

async fn stored(state: &AppState, d: &Device) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> {
    db::get_device(&state.db_pool, &text_id::encode_base32_crockford(&d.id))
        .await
        .expect("get_device")
}

/// ANTI-VACUITY, and the acceptance half of the gate: a correctly generated
/// canonical binding is accepted AND persisted. Without this, a handler that
/// refused everything would pass every rejection test below.
#[tokio::test]
async fn a_canonical_binding_is_accepted_and_persisted() {
    let state = make_state().await;
    let d = device(0x10);

    let res = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, valid_sig(&d)),
    )
    .await;
    assert!(res.is_ok(), "a valid canonical binding must register");

    let row = stored(&state, &d).await.expect("device row must exist");
    assert_eq!(
        row.2, d.kyber_pk,
        "the Kyber key must be persisted verbatim"
    );
    assert!(!row.3.is_empty(), "the binding signature must be persisted");
}

/// A FORGERY: a well-formed signature by the right key over the wrong message.
/// `sphincs_verify` answers `Ok(false)` here, not `Err` — so a handler that
/// tested "no error" rather than `Ok(true)` would accept it.
#[tokio::test]
async fn a_forged_binding_is_refused_and_nothing_is_persisted() {
    let state = make_state().await;
    let d = device(0x20);

    let forged = d.ak.sign(b"a different message entirely").expect("sign");
    let res = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, forged),
    )
    .await;

    assert!(res.is_err(), "a forged binding must be refused");
    assert!(
        stored(&state, &d).await.is_none(),
        "a refused registration left a row behind — verification must happen \
         BEFORE persistence, not alongside it"
    );
}

/// KEY SUBSTITUTION — the attack the binding exists to stop. A valid signature
/// over key A is replayed with key B under the same device identity.
#[tokio::test]
async fn a_substituted_kyber_key_is_refused_and_nothing_is_persisted() {
    let state = make_state().await;
    let d = device(0x30);

    // Signature is over d.kyber_pk; the request carries a different key.
    let other_pk = vec![0xEEu8; KYBER_PK_LEN];
    let res = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &other_pk, valid_sig(&d)),
    )
    .await;

    assert!(res.is_err(), "a substituted Kyber key must be refused");
    assert!(
        stored(&state, &d).await.is_none(),
        "a substituted key was persisted — the node would serve it to peers"
    );
}

/// OLD-DOMAIN artifact: a binding signed under the pre-cut double-NUL digest
/// (impact-table row B4). It must fail, with no compatibility path.
#[tokio::test]
async fn an_old_domain_binding_is_refused() {
    let state = make_state().await;
    let d = device(0x40);

    let mut old = blake3::Hasher::new();
    old.update(b"DSM/kyber-identity-binding\0"); // literal carried its own NUL
    old.update(&[0u8]); // and the helper appended another
    old.update(&d.id);
    old.update(&d.genesis);
    old.update(&d.kyber_pk);
    let old_digest = *old.finalize().as_bytes();
    let stale = d.ak.sign(&old_digest).expect("sign old-domain");

    let res = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, stale),
    )
    .await;

    assert!(
        res.is_err(),
        "a binding signed under the pre-cut domain still registers — there is a \
         compatibility verifier that must not exist"
    );
    assert!(stored(&state, &d).await.is_none());
}

/// MALFORMED: a signature of the wrong length. `sphincs::verify` fails closed on
/// a length mismatch rather than erroring, so this also exercises the
/// `Ok(false)` path rather than the `Err` path.
#[tokio::test]
async fn a_malformed_binding_is_refused() {
    let state = make_state().await;
    let d = device(0x50);

    let res = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, vec![0u8; 7]),
    )
    .await;

    assert!(
        res.is_err(),
        "a truncated binding signature must be refused"
    );
    assert!(stored(&state, &d).await.is_none());
}

/// A binding signed by a DIFFERENT AK than the one presented as `pubkey`.
#[tokio::test]
async fn a_binding_signed_by_another_key_is_refused() {
    let state = make_state().await;
    let d = device(0x60);
    let impostor = device(0x61);

    let digest = canonical_binding_digest(&d.id, &d.genesis, &d.kyber_pk);
    let wrong_signer = impostor.ak.sign(&digest).expect("sign");

    let res = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, wrong_signer),
    )
    .await;

    assert!(
        res.is_err(),
        "a binding signed by another AK must be refused"
    );
    assert!(stored(&state, &d).await.is_none());
}

/// RELOAD does not bypass verification. A row that was accepted stays readable
/// across a fresh read, and — critically — a rejected registration cannot be
/// "completed" by retrying without a valid binding.
#[tokio::test]
async fn a_rejected_registration_cannot_be_completed_by_retrying() {
    let state = make_state().await;
    let d = device(0x70);

    // Rejected.
    let bad = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, vec![0xABu8; 64]),
    )
    .await;
    assert!(bad.is_err());
    assert!(stored(&state, &d).await.is_none());

    // Retrying with the same invalid binding is still refused — no partial row
    // from the first attempt makes the second one succeed.
    let again = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, vec![0xABu8; 64]),
    )
    .await;
    assert!(again.is_err());
    assert!(stored(&state, &d).await.is_none());

    // A correct binding then registers cleanly, and reads back.
    let good = register_device(
        Extension(Arc::new(state.clone())),
        request(&d, &d.kyber_pk, valid_sig(&d)),
    )
    .await;
    assert!(
        good.is_ok(),
        "a valid binding must register after rejections"
    );

    let row = stored(&state, &d).await.expect("row after success");
    assert_eq!(row.2, d.kyber_pk);
}
