// SPDX-License-Identifier: MIT OR Apache-2.0
//! `offline_bearer_attestation` must survive a restart, and must never be synthesized.
//!
//! The field is device AUTHORITY state, not canonical hash material — it does not enter
//! `root()`. It was nonetheless absent from the head codec entirely: `encode_device_state`
//! never wrote it and `DeviceState::restore` hardcodes `NotAttested`
//! (device_state.rs:886), so an `Attested` device came back `NotAttested` after every
//! reload. That is a persistence invariant violation regardless of who reads the field.
//!
//! Gate polarity is deny-unless-proven: only `Attested` permits the offline-bearer path.
//! So the failure was fail-closed — it removed authority rather than granting it — but
//! silently dropping authority state is still dropping state, and it makes "the
//! offline-bearer path survives a restart" unprovable.
//!
//! The negative direction is the one that must never regress: absence or corruption has
//! to fail closed, never decode as attested.

#![allow(clippy::disallowed_methods)]

use dsm::types::device_state::{DeviceState, OfflineBearerAttestation};
use dsm_sdk::storage::client_db::{decode_device_state, encode_device_state};

const GENESIS: [u8; 32] = [0x11; 32];
const DEVID: [u8; 32] = [0x22; 32];

/// A head carrying real material, so the round trip is not vacuous.
fn head_with(attestation: OfflineBearerAttestation) -> DeviceState {
    use dsm::core::bilateral_transaction_manager::{compute_smt_key, initial_chain_tip_from_device_ids};
    use dsm::types::device_state::{BalanceDelta, BalanceDirection};

    let policy = dsm::core::token::builtin_policy_commit_for_token("ERA").expect("ERA");
    let base = DeviceState::new(GENESIS, DEVID, vec![0xAA; 64], 64);
    let mut head = base
        .advance(
            compute_smt_key(&DEVID, &DEVID),
            DEVID,
            dsm::types::operations::Operation::Mint {
                amount: dsm::types::token_types::Balance::from_state(275, [0u8; 32]),
                token_id: b"ERA".to_vec(),
                policy_commit: policy,
                authorized_by: b"self".to_vec(),
                proof_of_authorization: Vec::new(),
                message: "seed".to_string(),
            },
            vec![0x33; 32],
            None,
            &[BalanceDelta {
                policy_commit: policy,
                direction: BalanceDirection::Credit,
                amount: 275,
            }],
            Some(initial_chain_tip_from_device_ids(&DEVID, &DEVID)),
            None,
            None,
            None,
        )
        .expect("mint advance")
        .new_device_state;
    head.set_offline_bearer_attestation(attestation);
    head
}

/// THE ACCEPTANCE CRITERION.
///
/// `Attested` -> encode the authoritative head -> restore -> still `Attested`, with the
/// same state, and the head otherwise intact.
#[test]
fn attested_survives_encode_and_restore() {
    let before = head_with(OfflineBearerAttestation::Attested);
    assert_eq!(
        before.offline_bearer_attestation(),
        OfflineBearerAttestation::Attested,
        "precondition"
    );

    let (after, stored_root) = decode_device_state(&encode_device_state(&before)).expect("decode");

    assert_eq!(
        after.offline_bearer_attestation(),
        OfflineBearerAttestation::Attested,
        "an Attested device must come back Attested — this is the whole invariant"
    );
    assert!(
        after.offline_bearer_attestation().permits_offline_bearer(),
        "and it must still permit the offline-bearer path"
    );

    // The rest of the head is unchanged: attestation is not canonical hash material, so
    // persisting it must not perturb the root.
    assert_eq!(after.root(), stored_root, "recomputed root == stored root");
    assert_eq!(
        after.root(),
        before.root(),
        "attestation is not in the root"
    );
    assert_eq!(after.balances_snapshot(), before.balances_snapshot());
    assert_eq!(
        after.relationship_keys().len(),
        before.relationship_keys().len()
    );
}

/// `NotAttested` remains `NotAttested` — the round trip must not drift in either
/// direction, and must not quietly upgrade a device that proved it has no island.
#[test]
fn not_attested_remains_not_attested() {
    let before = head_with(OfflineBearerAttestation::NotAttested);
    let (after, _) = decode_device_state(&encode_device_state(&before)).expect("decode");
    assert_eq!(
        after.offline_bearer_attestation(),
        OfflineBearerAttestation::NotAttested
    );
    assert!(!after.offline_bearer_attestation().permits_offline_bearer());
}

/// `Unknown` (imported / capsule-restored, incomplete proof) also round-trips, and stays
/// denied. Losing the distinction between "proven absent" and "unproven" would erase the
/// reason the third state exists.
#[test]
fn unknown_round_trips_and_stays_denied() {
    let before = head_with(OfflineBearerAttestation::Unknown);
    let (after, _) = decode_device_state(&encode_device_state(&before)).expect("decode");
    assert_eq!(
        after.offline_bearer_attestation(),
        OfflineBearerAttestation::Unknown
    );
    assert!(!after.offline_bearer_attestation().permits_offline_bearer());
}

/// THE NEGATIVE CASE. A MISSING attestation must fail closed — never decode at all,
/// and above all never decode as attested.
#[test]
fn a_missing_attestation_fails_closed() {
    let bytes = encode_device_state(&head_with(OfflineBearerAttestation::Attested));
    let truncated = &bytes[..bytes.len() - 1];

    let err = decode_device_state(truncated).expect_err("a truncated head must not decode");
    let msg = format!("{err}");
    assert!(
        msg.contains("offline_bearer_attestation missing"),
        "the failure must name the missing attestation, got: {msg}"
    );
}

/// A MALFORMED attestation must fail closed. `0` is the case that matters most: it is
/// what a zero-filled or wrongly-sized tail yields, and it must not be readable as any
/// state — least of all `Attested`.
#[test]
fn a_malformed_attestation_fails_closed_and_never_synthesizes_attested() {
    let base = encode_device_state(&head_with(OfflineBearerAttestation::Attested));

    for bad in [0u8, 4, 5, 99, 255] {
        let mut bytes = base.clone();
        *bytes.last_mut().expect("non-empty") = bad;

        match decode_device_state(&bytes) {
            Err(e) => assert!(
                format!("{e}").contains("offline_bearer_attestation invalid tag"),
                "tag {bad}: must be refused as an invalid attestation, got: {e}"
            ),
            Ok((head, _)) => panic!(
                "tag {bad} decoded to {:?} — a malformed attestation must fail closed, \
                 never resolve to a state",
                head.offline_bearer_attestation()
            ),
        }
    }
}

/// The canonical wire tags are the only thing that can produce `Attested`, and `0` is
/// not one of them. This pins the property the negative cases rely on.
#[test]
fn only_the_canonical_tag_one_yields_attested() {
    assert_eq!(
        OfflineBearerAttestation::from_wire(1),
        Some(OfflineBearerAttestation::Attested)
    );
    for not_attested in [0, 4, -1, i32::MAX, i32::MIN] {
        assert_ne!(
            OfflineBearerAttestation::from_wire(not_attested),
            Some(OfflineBearerAttestation::Attested),
            "tag {not_attested} must never yield Attested"
        );
    }
}

/// THE COST, stated as a fact rather than a footnote: a v0x05 head — every head written
/// before this change, including the ones on the two rig handsets — no longer decodes.
///
/// The attestation is a new field in the head encoding, so `DEVICE_STATE_VERSION` goes
/// 0x05 -> 0x06 and the decoder's existing version gate refuses the old shape outright.
/// DSM beta does not migrate; the head and its signed chain-state archive live in the
/// client database and are NOT recoverable from the storage nodes, which are a
/// persistence layer and not an authority (ADR 0002). So this lands together with the
/// wipe/reseed that #635 already requires — not as a second, separate one.
#[test]
fn a_pre_v6_head_is_refused_rather_than_guessed_at() {
    let bytes = encode_device_state(&head_with(OfflineBearerAttestation::Attested));

    // Exactly a v0x05 blob: the old version byte, and no attestation tail.
    let mut old_format = bytes[..bytes.len() - 1].to_vec();
    old_format[0] = 0x05;

    let err = decode_device_state(&old_format).expect_err("a v5 head must not decode as v6");
    let msg = format!("{err}");
    assert!(
        msg.contains("unknown version 5") && msg.contains("expected 6"),
        "the refusal must name both versions so the operator knows to reseed, got: {msg}"
    );
}
