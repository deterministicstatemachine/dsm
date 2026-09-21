// SPDX-License-Identifier: Apache-2.0

//! P15-9 at the one seam both consumer paths share: **only an ordinary
//! single-root lineage is an eligible peer-debit source.**
//!
//! The rule is about LINEAGE, not about resolution state. A SoFi position
//! whose route resolved and selected a concrete root is fully validated, its
//! root is genuine, its witness is impeccable — and it is still refused. A
//! boolean like `is_unresolved` would let exactly that case through, which is
//! why the discriminant names where the position came from instead.
//!
//! The boundary has two halves and they are proven in two places:
//!
//! ```text
//! unresolved SoFi -> the WALK refuses; no ValidatedPeerTransition exists.
//!                    Proven by peer_lineage's own
//!                    `no_validated_root_is_minted_from_either_branch_of_an_unresolved_claim`,
//!                    and made structurally impossible here by the absence of
//!                    an `UnresolvedSofi` arm.
//! resolved SoFi   -> a transition may exist; the DEBIT GATE refuses it.
//!                    Proven below.
//! ```
//!
//! **No production path constructs `ResolvedSofi` today.** That is deliberate
//! (E1c-3): `validate_peer_lineage` refuses every conditional claim, resolved
//! or not, because resolution is verifier-local and never rewrites the `C_q`
//! register cell. The refusal is installed now so that when E2/E3 teaches the
//! walk to traverse a resolved SoFi position, P15-9 does not silently
//! disappear at the moment it starts mattering. These tests therefore drive
//! the arm through the `testing`-gated constructor — a dev-dependency-only
//! feature that cannot reach a production artifact, with
//! `ci/peer_debit_lineage_authoritative.sh` holding that line.

#![allow(clippy::disallowed_methods)]

use dsm::economic::lineage::{AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::economic::mutation::EconomicLeafMutation;
use dsm::economic::provenance::{prevalidate_sender_debit, ProvenanceError, ValidatedPeerTransition};
use dsm::economic::state::{EconomicBalanceState, EconomicLeafState};
use dsm::economic::tree::EconomicSmt;
use dsm::economic::witness::EconomicTransitionWitness;
use dsm::types::token_types::Balance;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};

const G_SENDER: [u8; 32] = [0x51; 32];
const DEV_SENDER: [u8; 32] = [0x52; 32];
const DEV_CONSUMER: [u8; 32] = [0x53; 32];
const ERA: [u8; 32] = [0xEE; 32];
const DEBIT: u64 = 25;

fn online_transfer_to_consumer() -> Operation {
    Operation::Transfer {
        to_device_id: DEV_CONSUMER.to_vec(),
        amount: Balance::from_state(DEBIT, [0u8; 32]),
        token_id: b"ERA".to_vec(),
        policy_commit: ERA,
        mode: TransactionMode::Bilateral,
        nonce: vec![9; 32],
        verification: VerificationType::Standard,
        pre_commit: None,
        recipient: Vec::new(),
        to: Vec::new(),
        message: String::new(),
        signature: Vec::new(),
        // `None` is what makes it ONLINE. The seam refuses anything else.
        authority_policy: None,
    }
}

/// The identical evidence behind both arms: one exact debit of `DEBIT` ERA by
/// an online Transfer addressed to the consumer.
///
/// Both transitions below are built from THIS, so the only thing that can
/// differ between the eligible and the refused case is the lineage. If the
/// refusal came from any other conjunct, the `SingleRoot` case would fail too.
fn facts() -> (ValidatedEconomicRoot, EconomicTransitionWitness, Operation) {
    let operation = online_transfer_to_consumer();
    let mut tree = EconomicSmt::new();
    let pre = EconomicLeafState::Balance(EconomicBalanceState::new(ERA, 100).unwrap());
    let key = pre.leaf_key(&G_SENDER, &DEV_SENDER);
    tree.insert(key, pre.leaf_value().unwrap());
    let pre_root = tree.root();
    let post = EconomicLeafState::Balance(EconomicBalanceState::new(ERA, 100 - DEBIT).unwrap());
    let siblings = tree.siblings(&key).to_vec();
    let mutation = EconomicLeafMutation::new(Some(pre), Some(post.clone()), siblings).unwrap();
    tree.insert(key, post.leaf_value().unwrap());
    let witness = EconomicTransitionWitness::new(
        pre_root,
        tree.root(),
        [0x0E; 32],
        dsm::economic::admission::dsm_operation_digest(&operation.to_bytes()),
        vec![mutation],
        Vec::new(),
    )
    .unwrap();
    let root = ValidatedEconomicRoot::rehydrate_from_admitted_store(
        AdmittedEconomicPosition::SingleRoot {
            economic_position: 4,
            economic_root: tree.root(),
        },
    )
    .expect("an ordinary admitted position");
    (root, witness, operation)
}

fn single_root() -> ValidatedPeerTransition {
    let (root, witness, operation) = facts();
    ValidatedPeerTransition::single_root_for_test(
        G_SENDER,
        DEV_SENDER,
        root,
        witness,
        vec![0xAA; 64],
        [0xC5; 32],
        [0xC1; 32],
        operation,
    )
}

/// The same evidence, relabelled as the lineage P15-9 refuses. Note that
/// `rehydrate_from_admitted_store` accepts `ResolvedSofi` and yields a
/// perfectly ordinary `ValidatedEconomicRoot` — a resolved route really does
/// select one concrete root, which is exactly why resolution state is the
/// wrong discriminator.
fn resolved_sofi() -> ValidatedPeerTransition {
    let (_, witness, operation) = facts();
    let mut tree = EconomicSmt::new();
    let pre = EconomicLeafState::Balance(EconomicBalanceState::new(ERA, 100).unwrap());
    let key = pre.leaf_key(&G_SENDER, &DEV_SENDER);
    tree.insert(key, pre.leaf_value().unwrap());
    let post = EconomicLeafState::Balance(EconomicBalanceState::new(ERA, 100 - DEBIT).unwrap());
    tree.insert(key, post.leaf_value().unwrap());
    let root = ValidatedEconomicRoot::rehydrate_from_admitted_store(
        AdmittedEconomicPosition::ResolvedSofi {
            economic_position: 4,
            selected_root: tree.root(),
            fulfillment_id: [0xF1; 32],
        },
    )
    .expect("a resolved route selected exactly one root");
    ValidatedPeerTransition::resolved_sofi_for_test(
        G_SENDER,
        DEV_SENDER,
        root,
        witness,
        vec![0xAA; 64],
        [0xC5; 32],
        [0xC1; 32],
        operation,
    )
}

fn prevalidate(t: &ValidatedPeerTransition) -> Result<(), ProvenanceError> {
    prevalidate_sender_debit(t, &G_SENDER, &DEV_SENDER, 0, &DEV_CONSUMER).map(|_| ())
}

/// THE POSITIVE CONTROL. Without it the refusal below proves nothing: every
/// input would be refused and the test would pass with the gate removed.
#[test]
fn an_ordinary_single_root_lineage_is_an_eligible_debit_source() {
    let debit = prevalidate_sender_debit(&single_root(), &G_SENDER, &DEV_SENDER, 0, &DEV_CONSUMER)
        .expect("a single-root peer with an exact online debit is eligible");
    assert_eq!(debit.debit_asset(), ERA);
    assert_eq!(debit.debit_amount(), DEBIT);
}

/// THE RULING. Same witness, same operation, same amount, a concrete selected
/// root — refused purely for descending from a SoFi route.
#[test]
fn a_resolved_sofi_lineage_is_refused_even_with_a_valid_concrete_root() {
    assert!(
        matches!(
            prevalidate(&resolved_sofi()),
            Err(ProvenanceError::SofiLineageNotEligible)
        ),
        "a resolved SoFi position must be refused on lineage, not tolerated \
         because its route happened to resolve"
    );
}

/// The refusal is about LINEAGE and nothing else. Both transitions are built
/// from one `facts()`, so this pins that the eligible and refused cases differ
/// in exactly one bit: had the refusal come from the witness, the operation,
/// the amount or the recipient, the single-root case above would be red too.
#[test]
fn the_two_lineages_differ_in_nothing_but_their_lineage() {
    let (eligible, refused) = (single_root(), resolved_sofi());
    assert_eq!(
        eligible.witness().post_economic_root,
        refused.witness().post_economic_root
    );
    assert_eq!(eligible.verified_operation(), refused.verified_operation());
    assert_eq!(
        eligible.validated_root().economic_root(),
        refused.validated_root().economic_root()
    );
    assert_eq!(
        eligible.validated_root().economic_position(),
        refused.validated_root().economic_position()
    );
    assert!(prevalidate(&eligible).is_ok());
    assert!(prevalidate(&refused).is_err());
}

/// P15-9 is checked BEFORE the other conjuncts, so a SoFi lineage is refused
/// for being a SoFi lineage rather than incidentally failing something else.
/// A gate that only fires when the rest already passed is a gate that reports
/// the wrong reason the day the rest stops passing.
#[test]
fn the_lineage_refusal_precedes_every_other_conjunct() {
    // A mutation index far out of range: on a single-root peer that is
    // `IndexOutOfRange`, and on a SoFi peer it must STILL be the lineage.
    let single =
        prevalidate_sender_debit(&single_root(), &G_SENDER, &DEV_SENDER, 99, &DEV_CONSUMER);
    assert!(matches!(
        single,
        Err(ProvenanceError::IndexOutOfRange { .. })
    ));
    let sofi =
        prevalidate_sender_debit(&resolved_sofi(), &G_SENDER, &DEV_SENDER, 99, &DEV_CONSUMER);
    assert!(matches!(sofi, Err(ProvenanceError::SofiLineageNotEligible)));
}

/// Facts cannot be lifted out of one arm and re-wrapped in the other, so an
/// eligible lineage cannot be manufactured from a refused one. This is a
/// STRUCTURAL claim, and it is held by the type: every accessor returns a
/// borrow, and `PeerTransitionFacts` has no public constructor and no way out.
///
/// The test that would break this does not compile, which is the point; what
/// is asserted at runtime is the observable consequence.
#[test]
fn a_refused_lineage_cannot_be_relabelled_as_an_eligible_one() {
    let refused = resolved_sofi();
    // Exhaustive on purpose: adding a third arm to `ValidatedPeerTransition`
    // fails to compile HERE and in `prevalidate_sender_debit`, forcing a
    // ruling on whether the new lineage is debit-eligible.
    match &refused {
        ValidatedPeerTransition::SingleRoot(_) => panic!("built as ResolvedSofi"),
        ValidatedPeerTransition::ResolvedSofi(_) => {}
    }
    assert!(prevalidate(&refused).is_err());
}
