// SPDX-License-Identifier: Apache-2.0

//! The register, the claim envelope, and the validated/registered separation.
//!
//! The theme throughout: **registering is not validating**. A member's job is
//! attribution and storage; nothing here decides whether a root is the result
//! of a valid transition, and the type system is what keeps the two apart.

#![allow(clippy::disallowed_methods)]

use dsm::ccb::genesis::sigalg;
use dsm::economic::claim::EconomicRootClaimBody;
use dsm::economic::claim_envelope::{
    decode_and_verify_economic_root_claim, sign_economic_root_claim, verify_claim_attribution,
    ClaimEnvelopeError,
};
use dsm::economic::lineage::{activate, EconomicActivationSnapshot};
use dsm::economic::register::{
    economic_root_register_key, resolve_for_trader, resolve_root_register_profile,
    AttributionError, AuthenticatedCaller, RegisteredEconomicRoot, RegisterResolutionError,
};
use dsm::economic::tree::empty_economic_root;

const G: [u8; 32] = [0x11; 32];
const DEV: [u8; 32] = [0x22; 32];

// ── Register cell identity ─────────────────────────────────────────────────

/// `K_root` identity-SCOPES the cell. It confers no exclusivity: every input is
/// public, so the coordinate is derivable by anyone. Preventing a third party
/// from writing there is `verify_claim_attribution`'s job, tested separately.
#[test]
fn each_position_of_each_identity_is_its_own_cell() {
    let at0 = economic_root_register_key(&G, &DEV, 0);
    let at1 = economic_root_register_key(&G, &DEV, 1);
    assert_ne!(at0, at1, "positions must not share a write-once cell");
    assert_ne!(
        at0,
        economic_root_register_key(&[0x99; 32], &DEV, 0),
        "a different genesis is a different cell"
    );
    assert_ne!(
        at0,
        economic_root_register_key(&G, &[0x99; 32], 0),
        "a different device is a different cell"
    );
    assert_eq!(
        at0,
        economic_root_register_key(&G, &DEV, 0),
        "deterministic"
    );
}

// ── Network-scoped resolution, fail closed ─────────────────────────────────

#[test]
fn the_beta_register_resolves_to_the_three_member_fleet_at_q_two() {
    let p = resolve_root_register_profile(b"dsm-testnet").expect("known network");
    assert_eq!(p.members.len(), 3);
    assert_eq!(p.quorum, 2);
    // The set id is a re-derivation over the members, not a constant somebody
    // typed — so a member list that drifts changes the id rather than silently
    // resolving the old register.
    let members: Vec<&[u8]> = p.members.iter().map(|m| m.as_slice()).collect();
    let set = dsm::ccb::StorageSetMembers::new(&members).expect("valid set");
    assert_eq!(p.storage_set_id, dsm::ccb::storage_set_id(&set).unwrap());
}

#[test]
fn an_unknown_network_fails_closed_rather_than_defaulting() {
    // A default register is a register an attacker can steer traffic into.
    match resolve_root_register_profile(b"testnet") {
        Err(RegisterResolutionError::UnknownNetwork { network_id }) => {
            assert_eq!(network_id, b"testnet".to_vec());
        }
        other => panic!("an unknown network must fail closed, got {other:?}"),
    }
}

#[test]
fn a_trader_cannot_settle_under_a_network_it_did_not_commit_to() {
    // The substitution this exists to stop: mint a genesis under some other
    // network whose profile names a different register, then present roots
    // from that register as though they came from this one.
    match resolve_for_trader(b"othernet", b"dsm-testnet") {
        Err(RegisterResolutionError::NetworkMismatch { claimed, expected }) => {
            assert_eq!(claimed, b"othernet".to_vec());
            assert_eq!(expected, b"dsm-testnet".to_vec());
        }
        other => panic!("a network mismatch must be refused, got {other:?}"),
    }
    assert!(resolve_for_trader(b"dsm-testnet", b"dsm-testnet").is_ok());
}

// ── The claim envelope ─────────────────────────────────────────────────────

fn keypair() -> (Vec<u8>, Vec<u8>) {
    dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
}

fn body(pk: &[u8], set_id: [u8; 32]) -> EconomicRootClaimBody {
    EconomicRootClaimBody::new(
        G,
        DEV,
        7,
        [0x33; 32],
        [0x44; 32],
        set_id,
        sigalg::SPHINCS_PLUS_SPX256F,
        pk,
    )
    .expect("valid body")
}

#[test]
fn a_signed_claim_round_trips_and_a_tampered_one_does_not() {
    let (pk, sk) = keypair();
    let set = resolve_root_register_profile(b"dsm-testnet")
        .unwrap()
        .storage_set_id;
    let b = body(&pk, set);
    let envelope = sign_economic_root_claim(&b, &sk).expect("signable");

    let verified = decode_and_verify_economic_root_claim(&envelope).expect("verifies");
    assert_eq!(verified.body, b);
    assert_eq!(
        verified.envelope_bytes, envelope,
        "the member stores the EXACT bytes; a re-encode is a different value at a write-once cell"
    );

    // A suffix is not a claim with a suffix.
    let mut extended = envelope.clone();
    extended.push(0x00);
    assert!(matches!(
        decode_and_verify_economic_root_claim(&extended),
        Err(ClaimEnvelopeError::Malformed(_))
    ));

    // Flip a byte inside the signature.
    let mut tampered = envelope.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xFF;
    assert!(matches!(
        decode_and_verify_economic_root_claim(&tampered),
        Err(ClaimEnvelopeError::SignatureInvalid) | Err(ClaimEnvelopeError::Malformed(_))
    ));
}

#[test]
fn a_claim_signed_for_one_position_does_not_verify_at_another() {
    // The signed body commits the position, so a claim cannot be replayed into
    // a neighbouring cell to burn it.
    let (pk, sk) = keypair();
    let set = resolve_root_register_profile(b"dsm-testnet")
        .unwrap()
        .storage_set_id;
    let at7 = body(&pk, set);
    let envelope = sign_economic_root_claim(&at7, &sk).expect("signable");
    let verified = decode_and_verify_economic_root_claim(&envelope).expect("verifies");

    assert_eq!(verified.body.economic_position, 7);
    assert_ne!(
        economic_root_register_key(&G, &DEV, verified.body.economic_position),
        economic_root_register_key(&G, &DEV, 8)
    );
}

// ── Member-side attribution ────────────────────────────────────────────────

#[test]
fn a_member_refuses_a_claim_that_is_not_the_callers() {
    let (pk, sk) = keypair();
    let set = resolve_root_register_profile(b"dsm-testnet")
        .unwrap()
        .storage_set_id;
    let envelope = sign_economic_root_claim(&body(&pk, set), &sk).expect("signable");
    let claim = decode_and_verify_economic_root_claim(&envelope).expect("verifies");

    let caller = AuthenticatedCaller {
        public_key: pk.clone(),
        device_id: DEV,
    };
    assert!(verify_claim_attribution(&claim, &caller, &set).is_ok());

    // Signature-valid, but written by someone else. This — not K_root — is
    // what prevents third-party preemption: the cell coordinate is derivable
    // by anyone holding the victim's public (G, DevID, position), so only the
    // attribution refusal stops a write that would burn the cell forever.
    let impostor = AuthenticatedCaller {
        public_key: keypair().0,
        device_id: DEV,
    };
    assert_eq!(
        verify_claim_attribution(&claim, &impostor, &set).unwrap_err(),
        AttributionError::ClaimantIsNotCaller
    );

    let wrong_device = AuthenticatedCaller {
        public_key: pk,
        device_id: [0x99; 32],
    };
    assert_eq!(
        verify_claim_attribution(&claim, &wrong_device, &set).unwrap_err(),
        AttributionError::DeviceIsNotCaller
    );

    // A member refuses a claim addressed to a register it is not part of.
    let other_set = [0x77; 32];
    assert!(matches!(
        verify_claim_attribution(&claim, &caller, &other_set).unwrap_err(),
        AttributionError::WrongStorageSet { .. }
    ));
}

// ── Activation ─────────────────────────────────────────────────────────────

#[test]
fn a_fresh_identity_activates_at_the_canonical_empty_root() {
    let v = activate(EconomicActivationSnapshot::fresh()).expect("fresh device activates");
    assert_eq!(v.economic_position(), 0);
    assert_eq!(
        v.economic_root(),
        empty_economic_root(),
        "position 0 is verifier-derived, never trader-chosen"
    );
}

/// One way a device can be holding value, applied to an otherwise-fresh snapshot.
type DirtySnapshot = fn(&mut EconomicActivationSnapshot);

#[test]
fn a_device_already_holding_value_cannot_call_its_holdings_position_zero() {
    // Each field independently blocks activation. Snapshotting current
    // holdings as position 0 would let the device assert its own opening
    // balances — self-rooting at the base of the lineage.
    let cases: [(&str, DirtySnapshot); 4] = [
        ("balances", |s| s.online_balances_empty = false),
        ("reserves", |s| s.vault_reserves_empty = false),
        ("receipts", |s| s.settlement_receipt_state_empty = false),
        ("allocation", |s| s.outstanding_offline_allocation = true),
    ];
    for (name, dirty) in cases {
        let mut snapshot = EconomicActivationSnapshot::fresh();
        dirty(&mut snapshot);
        assert!(
            activate(snapshot).is_err(),
            "{name} must block activation, and did not"
        );
    }
}

// ── Registered is not validated ────────────────────────────────────────────

#[test]
fn registering_an_arbitrary_root_yields_nothing_validated() {
    // A malicious trader registers a root it invented, perfectly consistently.
    // The register accepts it — non-equivocation is all it establishes.
    let registered = RegisteredEconomicRoot {
        trader_genesis: G,
        trader_devid: DEV,
        economic_position: 1,
        post_economic_root: [0xEE; 32], // invented
        admission_manifest_addr: [0xDD; 32],
        storage_set_id: resolve_root_register_profile(b"dsm-testnet")
            .unwrap()
            .storage_set_id,
    };
    assert_eq!(
        registered.register_key(),
        economic_root_register_key(&G, &DEV, 1)
    );

    // There is deliberately NO API turning that into a ValidatedEconomicRoot:
    // no From, no into_validated, no assume_valid. The only constructor is
    // `activate`, which yields position 0 at the empty root and knows nothing
    // about this registration.
    let validated = activate(EconomicActivationSnapshot::fresh()).expect("fresh");
    assert_eq!(validated.economic_position(), 0);
    assert_ne!(
        validated.economic_root(),
        registered.post_economic_root,
        "a registered root is not thereby a validated one"
    );
}

#[test]
fn a_decodable_but_noncanonical_envelope_is_refused() {
    // The case a trailing garbage byte does NOT cover: prost SKIPS unknown
    // fields, so this decodes cleanly and only the re-encode comparison
    // catches it. At a write-once cell that matters more than usual — two
    // byte-different encodings of "the same" claim are two different values,
    // so a member accepting a padded one would store bytes that can never win
    // a quorum against the canonical form.
    let (pk, sk) = keypair();
    let set = resolve_root_register_profile(b"dsm-testnet")
        .unwrap()
        .storage_set_id;
    let envelope = sign_economic_root_claim(&body(&pk, set), &sk).expect("signable");
    assert!(decode_and_verify_economic_root_claim(&envelope).is_ok());

    // Append unknown field 3, wire type 0 (varint), value 1.
    let mut padded = envelope.clone();
    padded.extend_from_slice(&[0x18, 0x01]);

    match decode_and_verify_economic_root_claim(&padded) {
        Err(ClaimEnvelopeError::Malformed(why)) => assert_eq!(
            why, "envelope is not canonical",
            "must be caught by the re-encode comparison, not by a decode failure"
        ),
        other => panic!("a non-canonical envelope must be refused, got {other:?}"),
    }
}
