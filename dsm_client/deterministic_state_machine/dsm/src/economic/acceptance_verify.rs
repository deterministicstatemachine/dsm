// SPDX-License-Identifier: Apache-2.0

//! `TA_B` VERIFICATION — amendment 2c-D §7's seven ordered conjuncts.
//!
//! This is what turns a conformant `TraderAcceptance` from a serialization
//! fact into evidence. Success yields a [`BundleAcceptanceWitness`], which is
//! the conjunct `IndependentRealization` has been waiting for since 2c-C4
//! defined it without a way to construct one.
//!
//! ## The order is normative, and each step may use only what the ones above
//! it established
//!
//! ```text
//! 1  decode and shape        discharged by TraderAcceptance's own constructor
//! 2  authenticate G          HERE — sigma_dsm under the proven AK
//! 3  derive R_T^+            SUPPLIED as ValidatedEconomicRoot
//! 4  require the successor   SUPPLIED inside MarketCorrespondence (CORR.1-3)
//! 5  bind the operation id,
//!    then fold the path      HERE
//! 6  obtain b and bind it    HERE
//! 7  bind the economics      SUPPLIED inside MarketCorrespondence (CORR.4)
//! ```
//!
//! **Steps 3, 4 and 7 are parameters, not omissions.** 2c-C4 §5 refused the
//! shape where a conjunct is supplied at each call site rather than as a
//! constructor parameter, *"because a parameter cannot be forgotten at a call
//! site the way a conjunction can"*. So each is a type only its own verifier
//! can produce: a [`ValidatedEconomicRoot`] comes from the walk, and a
//! [`MarketCorrespondence`] exists only because `check_market_correspondence`
//! returned it. Holding them IS the fact that those steps held.
//!
//! Re-deriving steps 4 and 7 here would be worse than redundant. `CORR.4`
//! already compares the accepted operation's `effects_digest` against the
//! bundle's `route_effects_digest`; a second comparison written here would be
//! a **second acceptance predicate beside the frozen one**, which is exactly
//! what amendment 2c-C3's commit sequence warns against.
//!
//! ## What this does NOT establish
//!
//! A witness says the acceptance is authentic and names this bundle. It does
//! **not** say the bundle is binding-final — that is the QuorumBind register's
//! fact and 2c-D §7's closing sentence keeps them apart: *"A `TA_B` satisfying
//! all seven realizes `B`, and only together with `B` being binding-final.
//! Acceptance is a precondition of realization, never its trigger."* Nothing
//! here releases a fence or publishes a receipt.

use crate::ccb::MarketTerms;
use crate::crypto::sphincs::sphincs_verify;
use crate::dlv::successor_validity::{BundleAcceptanceWitness, MarketCorrespondence};
use crate::economic::faucet::{dsm_economic_operation_id, dsm_operation_digest};
use crate::economic::keys::bundle_acceptance_key;
use crate::economic::lineage::ValidatedEconomicRoot;
use crate::economic::state::EconomicLeafState;
use crate::economic::successor_evidence::substrate_signing_digest;
use crate::economic::trader_acceptance::TraderAcceptance;
use crate::economic::tree::{leaf_node, root_from_path, ECONOMIC_SMT_HEIGHT};
use crate::types::operations::Operation;

/// Why an acceptance was refused.
///
/// **The INVALID / INCOMPLETE split is frozen and lives in the caller**, not
/// here: 2c-D §7 makes a step-2 failure INVALID and a step-3 walk failure
/// INCOMPLETE — retryable, never invalid. Every variant below is INVALID,
/// because step 3 is a parameter and its failure never reaches this function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptanceInvalid {
    /// The carried `operation_bytes` are not a canonical `DlvSettle`.
    OperationNotCanonical,
    /// `sigma_dsm` does not verify under the independently established AK, so
    /// the carried `G` is not authenticated.
    GenesisNotAuthenticated,
    /// The leaf, the witness and the recomputation disagree about which
    /// economic operation this acceptance belongs to.
    OperationIdentityDisagrees {
        leaf: [u8; 32],
        recomputed: [u8; 32],
    },
    /// The acceptance path does not fold to the validated economic root.
    PathDoesNotFoldToTheValidatedRoot {
        folded: [u8; 32],
        validated: [u8; 32],
    },
    /// The authenticated leaf names a different bundle than the one being
    /// composed.
    LeafNamesAnotherBundle { leaf: [u8; 32], composing: [u8; 32] },
    /// The acceptance leaf has no canonical encoding.
    LeafNotEncodable,
}

impl core::fmt::Display for AcceptanceInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OperationNotCanonical => write!(
                f,
                "the carried operation bytes are not a canonical DlvSettle, so no signing \
                 digest over them would mean anything"
            ),
            Self::GenesisNotAuthenticated => write!(
                f,
                "sigma_dsm does not verify under the established trader authority, so the \
                 carried genesis stays a supplied value and cannot key a leaf"
            ),
            Self::OperationIdentityDisagrees { leaf, recomputed } => write!(
                f,
                "the acceptance leaf names operation {leaf:02x?} but the accepted transition \
                 recomputes to {recomputed:02x?}"
            ),
            Self::PathDoesNotFoldToTheValidatedRoot { folded, validated } => write!(
                f,
                "the acceptance path folds to {folded:02x?}, not to the validated economic root \
                 {validated:02x?}"
            ),
            Self::LeafNamesAnotherBundle { leaf, composing } => write!(
                f,
                "the authenticated leaf commits bundle {leaf:02x?} while {composing:02x?} is \
                 being composed"
            ),
            Self::LeafNotEncodable => {
                write!(f, "the acceptance leaf has no canonical encoding")
            }
        }
    }
}

/// **2c-D §7.** Verify one `TA_B` against the bundle being composed.
///
/// `b` is the identity of that bundle, `terms` its market terms, `proven_ak`
/// the trader authority established INDEPENDENTLY of this artifact — never a
/// key the acceptance names, or the check would be of the artifact against
/// itself.
///
/// Returns the witness on success. There is no other way to obtain one.
pub fn verify_trader_acceptance(
    acceptance: &TraderAcceptance,
    terms: &MarketTerms,
    b: [u8; 32],
    correspondence: &MarketCorrespondence,
    validated: &ValidatedEconomicRoot,
    proven_ak: &[u8],
) -> Result<BundleAcceptanceWitness, AcceptanceInvalid> {
    // Steps 4 and 7 arrived as `correspondence`. Named rather than silently
    // relied on, so a reader sees WHY they are absent from the body.
    let _ = correspondence;

    // ── STEP 2 — authenticate G ──────────────────────────────────────────
    //
    // Both operands come from the bundle and are already checked by G1-G4
    // (`check_market_evidence`), so neither is a fresh trust here.
    let evidence = &terms.recovery_material;
    let operation = Operation::from_bytes(&evidence.operation_bytes)
        .map_err(|_| AcceptanceInvalid::OperationNotCanonical)?;
    if operation.to_bytes() != evidence.operation_bytes {
        return Err(AcceptanceInvalid::OperationNotCanonical);
    }
    let Operation::DlvSettle { settler_devid, .. } = operation else {
        return Err(AcceptanceInvalid::OperationNotCanonical);
    };

    // THE CONJUNCT G1-G4 DO NOT SUPPLY, enforced STRUCTURALLY rather than as
    // an equality.
    //
    // The signing digest must be built over the DevID being CREDITED. G4
    // recomputes the chain tip from `counterparty_devid`, so that field is the
    // one a verifier naturally reaches for — and it is the wrong one: it
    // equals the trader's DevID only under a self-loop shape nothing verifies
    // (2c-D §12). Reading `settler_devid` and never `counterparty_devid` makes
    // the property hold by construction, which is stronger than checking two
    // candidates agree, and it is why no `DevIdIsNotTheSettler` variant exists
    // to return. `an_acceptance_verifies_even_when_the_counterparty_is_not_the_settler`
    // is what would catch a regression to the wrong field.
    let devid = settler_devid;
    let c_dsm_plus = terms.trader_successor;
    let operation_digest = dsm_operation_digest(&evidence.operation_bytes);
    let genesis = acceptance.trader_genesis();

    let digest = substrate_signing_digest(&genesis, &devid, &c_dsm_plus, &operation_digest);
    let verified = sphincs_verify(proven_ak, &digest, evidence.sigma_dsm())
        .map_err(|_| AcceptanceInvalid::GenesisNotAuthenticated)?;
    if !verified {
        return Err(AcceptanceInvalid::GenesisNotAuthenticated);
    }
    // From here `genesis` and `devid` are AUTHENTICATED, and only now may they
    // derive a leaf key.

    // ── STEP 5 — bind the operation identity, then fold ──────────────────
    //
    // The three-way equality of §7 step 5. The middle term is the witness's
    // own id, which provenance requires to equal this recomputation; checking
    // the leaf against the witness alone would tie the acceptance to whatever
    // transition the witness happened to describe.
    let recomputed_id = dsm_economic_operation_id(&genesis, &devid, &c_dsm_plus);
    let leaf = acceptance.acceptance_leaf();
    if leaf.economic_operation_id != recomputed_id {
        return Err(AcceptanceInvalid::OperationIdentityDisagrees {
            leaf: leaf.economic_operation_id,
            recomputed: recomputed_id,
        });
    }

    let key = bundle_acceptance_key(&genesis, &devid, &recomputed_id);
    let value = EconomicLeafState::BundleAcceptance(leaf.clone())
        .leaf_value()
        .map_err(|_| AcceptanceInvalid::LeafNotEncodable)?;
    // `acceptance_path` is exactly ECONOMIC_SMT_HEIGHT by TraderAcceptance's
    // constructor, so this conversion cannot fail — but it is expressed as a
    // refusal rather than an unwrap, because a length invariant enforced
    // elsewhere is still an invariant this function depends on.
    let siblings: &[[u8; 32]; ECONOMIC_SMT_HEIGHT] = acceptance
        .acceptance_path()
        .try_into()
        .map_err(|_| AcceptanceInvalid::LeafNotEncodable)?;
    let folded = root_from_path(&key, &leaf_node(&key, Some(&value)), siblings);
    let validated_root = validated.economic_root();
    if folded != validated_root {
        return Err(AcceptanceInvalid::PathDoesNotFoldToTheValidatedRoot {
            folded,
            validated: validated_root,
        });
    }

    // ── STEP 6 — obtain b, and only now bind it ─────────────────────────
    //
    // `leaf.bundle` became authoritative when the fold above succeeded. Read
    // before that point it is a value someone wrote down.
    if leaf.bundle != b {
        return Err(AcceptanceInvalid::LeafNamesAnotherBundle {
            leaf: leaf.bundle,
            composing: b,
        });
    }

    Ok(BundleAcceptanceWitness::from_verified_acceptance(
        leaf.bundle,
        recomputed_id,
        validated_root,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ccb::{Allocation, DsmSuccessorEvidence, MarketTerms, Route, RouteLeg, TradeIntent};
    use crate::economic::state::EconomicBundleAcceptanceState;
    use crate::economic::trader_acceptance::TraderAcceptance;
    use crate::economic::tree::EconomicSmt;
    use crate::types::operations::TransactionMode;

    const G: [u8; 32] = [0x11; 32];
    const DEV: [u8; 32] = [0x22; 32];
    const COUNTERPARTY: [u8; 32] = [0x99; 32];
    const VAULT: [u8; 32] = [0x03; 32];
    const X: [u8; 32] = [0xA0; 32];
    const B: [u8; 32] = [0xB0; 32];

    fn settle_op(settler: [u8; 32]) -> Operation {
        Operation::DlvSettle {
            vault_id: VAULT.to_vec(),
            owner_public_key: vec![0x01; 64],
            owner_devid: [0x41; 32],
            owner_genesis: [0x42; 32],
            input_policy_commit: [0x10; 32],
            output_policy_commit: [0x20; 32],
            parent_sequence: 7,
            parent_binding: [0xC0; 32],
            route_commit_bytes: vec![0x09; 8],
            external_commitment_x: X,
            input_amount: 1_000,
            output_amount: 900,
            fee_bps: 30,
            sigma: [0x66; 32],
            settler_public_key: vec![0x02; 64],
            settler_devid: settler,
            settlement_receipt_id: crate::dlv::settlement_receipt_leaf::derive_receipt_id(
                &VAULT, &X,
            ),
            signature: vec![0x77; 48],
            mode: TransactionMode::Unilateral,
        }
    }

    /// A market terms whose `sigma_dsm` genuinely signs the digest §7 step 2
    /// reconstructs. `counterparty_devid` is a parameter so a test can make it
    /// DIFFER from the settler.
    fn terms_signed_by(
        sk: &[u8],
        settler: [u8; 32],
        counterparty: [u8; 32],
    ) -> (MarketTerms, [u8; 32]) {
        let op = settle_op(settler);
        let op_bytes = op.to_bytes();
        let c_dsm_plus = [0xC5; 32];
        let digest =
            substrate_signing_digest(&G, &settler, &c_dsm_plus, &dsm_operation_digest(&op_bytes));
        let sigma = crate::crypto::sphincs::sphincs_sign(sk, &digest).expect("sign");
        let evidence = DsmSuccessorEvidence::new(
            [0x77; 32],
            [0xC1; 32],
            counterparty,
            op_bytes,
            [0xE0; 32],
            sigma,
        )
        .expect("evidence");
        let terms = MarketTerms {
            intent: TradeIntent {
                token_in: [0x10; 32],
                amount_in: 1_000,
                token_out: [0x20; 32],
                exact_out: 900,
                fee_bps: 30,
                nonce: [0x5A; 32],
            },
            route_set_commitment: X,
            selected_route: Route::new(vec![RouteLeg::Single(Allocation {
                parent_binding: [0xC0; 32],
                delta_in: 1_000,
                delta_out: 900,
                encumbrance_claim: [0xE1; 32],
                fee_policy: crate::ccb::FeePolicy::new(30).expect("fee below denominator"),
            })])
            .expect("one leg"),
            trader_parent: [0xC1; 32],
            trader_successor: c_dsm_plus,
            recovery_material: evidence,
        };
        (terms, c_dsm_plus)
    }

    /// A leaf, its real path in a tree, and the root that path folds to — used
    /// as the validated root, so the fold in step 5 is a genuine check.
    fn leaf_and_root(
        eoid: [u8; 32],
        bundle: [u8; 32],
    ) -> (EconomicBundleAcceptanceState, Vec<[u8; 32]>, [u8; 32]) {
        let leaf = EconomicBundleAcceptanceState {
            bundle,
            economic_operation_id: eoid,
        };
        let state = EconomicLeafState::BundleAcceptance(leaf.clone());
        let key = bundle_acceptance_key(&G, &DEV, &eoid);
        let mut tree = EconomicSmt::new();
        let siblings = tree.siblings(&key).to_vec();
        tree.insert(key, state.leaf_value().expect("value"));
        (leaf, siblings, tree.root())
    }

    struct Fixture {
        acceptance: TraderAcceptance,
        terms: MarketTerms,
        validated: ValidatedEconomicRoot,
        ak: Vec<u8>,
    }

    fn fixture(settler: [u8; 32], counterparty: [u8; 32]) -> Fixture {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let (terms, c_dsm_plus) = terms_signed_by(&sk, settler, counterparty);
        let eoid = dsm_economic_operation_id(&G, &settler, &c_dsm_plus);
        let (leaf, path, root) = leaf_and_root(eoid, B);
        Fixture {
            acceptance: TraderAcceptance::new(G, 3, leaf, path).expect("well formed"),
            terms,
            validated: ValidatedEconomicRoot::rehydrate_from_admitted_store(3, root),
            ak: pk,
        }
    }

    /// A `MarketCorrespondence` for the tests. Steps 4 and 7 are its facts, so
    /// the tests below exercise only what §7 itself performs.
    fn correspondence() -> MarketCorrespondence {
        use crate::ccb::{
            EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy, StorageSetMembers, VaultStateV2,
        };
        use crate::dlv::successor_validity::{
            check_correspondence, check_market_correspondence, AcceptedTransition,
            BundleCoordinates,
        };
        let v = VaultStateV2 {
            owner_genesis_id: [1; 32],
            owner_device_id: [2; 32],
            vault_id: [3; 32],
            generation: 7,
            reserve_a: 10_000,
            reserve_b: 5_000,
            market_policy: MarketPolicy::beta_constant_product([0x10; 32], [0x20; 32])
                .expect("ordered pair"),
            release_policy: ReleasePolicy::beta_owner_local_full_close(),
            fee_policy: FeePolicy::new(30).expect("fee below denominator"),
            encumbrances: EncumbranceSet::empty(),
            iteration_budget: None,
            parent_state_commitment: [4; 32],
            owner_authority_transition_digest: [5; 32],
            storage_set: StorageSetMembers::new(&[(b"dsm-node-1".as_slice(), [9; 32])])
                .expect("one member"),
            quorum: 1,
        };
        let supplied = v.encode().expect("encode");
        let witness = check_correspondence(&v, [0xC0; 32], &supplied).expect("10.a");
        check_market_correspondence(
            &AcceptedTransition {
                embedded_parent: [0xC1; 32],
                c_dsm_plus: [0xC5; 32],
                external_commitment_x: X,
                parent_binding: [0xC0; 32],
                effects_digest: [0xEF; 32],
            },
            &BundleCoordinates {
                trader_parent: [0xC1; 32],
                trader_successor: [0xC5; 32],
                route_set_commitment: X,
                route_effects_digest: [0xEF; 32],
            },
            [0xC0; 32],
            witness,
        )
        .expect("CORR.1-5")
    }

    #[test]
    fn an_authentic_acceptance_yields_the_witness() {
        let f = fixture(DEV, DEV);
        let w = verify_trader_acceptance(
            &f.acceptance,
            &f.terms,
            B,
            &correspondence(),
            &f.validated,
            &f.ak,
        )
        .expect("§7 holds");
        assert_eq!(w.bundle(), B, "the witness names the authenticated bundle");
        assert_eq!(w.economic_root(), f.validated.economic_root());
    }

    /// **2c-D §12's gap, asserted rather than assumed.** The settle is NOT a
    /// self-loop here — the counterparty is a different device — and §7 must
    /// still verify, because it reads `settler_devid` and never
    /// `counterparty_devid`. A regression to the wrong field turns this red.
    #[test]
    fn an_acceptance_verifies_even_when_the_counterparty_is_not_the_settler() {
        let f = fixture(DEV, COUNTERPARTY);
        assert_ne!(f.terms.recovery_material.counterparty_devid, DEV);
        verify_trader_acceptance(
            &f.acceptance,
            &f.terms,
            B,
            &correspondence(),
            &f.validated,
            &f.ak,
        )
        .expect("§7 must not depend on the unverified self-loop shape");
    }

    /// A signature under another authority leaves `G` unauthenticated, and the
    /// refusal is INVALID rather than a weaker outcome.
    #[test]
    fn an_acceptance_signed_by_another_authority_is_refused() {
        let f = fixture(DEV, DEV);
        let (other_pk, _) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        assert_eq!(
            verify_trader_acceptance(
                &f.acceptance,
                &f.terms,
                B,
                &correspondence(),
                &f.validated,
                &other_pk,
            ),
            Err(AcceptanceInvalid::GenesisNotAuthenticated)
        );
    }

    /// A leaf naming another bundle is refused at step 6 — after the fold, so
    /// the value it names was authenticated before being rejected.
    #[test]
    fn an_acceptance_for_another_bundle_is_refused() {
        let f = fixture(DEV, DEV);
        assert!(matches!(
            verify_trader_acceptance(
                &f.acceptance,
                &f.terms,
                [0xB1; 32],
                &correspondence(),
                &f.validated,
                &f.ak,
            ),
            Err(AcceptanceInvalid::LeafNamesAnotherBundle { .. })
        ));
    }

    /// A path that folds somewhere other than the validated root is refused,
    /// which is what stops a well-formed leaf from being proven under a root
    /// nobody validated.
    #[test]
    fn a_path_that_folds_elsewhere_is_refused() {
        let f = fixture(DEV, DEV);
        let elsewhere = ValidatedEconomicRoot::rehydrate_from_admitted_store(3, [0x77; 32]);
        assert!(matches!(
            verify_trader_acceptance(
                &f.acceptance,
                &f.terms,
                B,
                &correspondence(),
                &elsewhere,
                &f.ak,
            ),
            Err(AcceptanceInvalid::PathDoesNotFoldToTheValidatedRoot { .. })
        ));
    }
}
