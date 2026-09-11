// SPDX-License-Identifier: Apache-2.0

//! REQ 21.16 — verifying a published settlement receipt against the
//! INDEPENDENTLY VALIDATED economic root `R_T^+` (amendment 2c-D; owner ruling
//! D4 as corrected 2026-09-11, recorded at 2c-C4 §9).
//!
//! ## Why this exists beside [`verify_trader_settlement_receipt`]
//!
//! That function reads `trader_genesis`, `trader_devid`, `trader_public_key`
//! and `post_root` **out of the receipt** and then checks the receipt against
//! them. Its own banner records what that is worth: *"the cheapest tree
//! satisfying the inclusion check has ONE leaf, so the honest-path fixture and
//! a forgery are byte-identical constructions — anyone holding a SPHINCS+
//! keypair can build both."* It establishes that a receipt is internally
//! consistent, which is **serialization authenticity, not settlement
//! authenticity**.
//!
//! ## Which root, and why it is not the device `post_root`
//!
//! D4 originally required the receipt's DEVICE-SMT leaf under an
//! independently established device `post_root`. Implementing the cutover
//! showed no such root exists on the settle path: `C_T^+` commits no root,
//! `sigma_dsm` signs none, the 0x0031 substrate carries none, the route
//! discards `child_r_a`, and the device SMT has no validity replay — so a
//! device root could at best be trader-SIGNED, which is provenance and never
//! validity. The one independently VALIDATED root is `R_T^+`, and the settle
//! write set already commits the receipt's facts under it as an
//! [`EconomicSettlementReceiptState`] leaf. That is what this verifier folds:
//!
//! ```text
//! validated settle -> deterministic economic write set
//!     -> EconomicSettlementReceiptState -> included under validated R_T^+
//!     <- exact correspondence -> published receipt
//! ```
//!
//! **The fold is the correspondence check.** The leaf is REBUILT from the
//! receipt's facts and keyed from the proven identity and the settlement being
//! verified; it folds to `R_T^+` only if every field equals what the write set
//! committed. There is no second copy of the facts here to compare against,
//! and so no list of equalities that could fall out of step with the leaf.
//!
//! **The receipt's legacy fields carry no weight.** `post_root`,
//! `smt_siblings`, `trader_public_key` and `trader_signature` are the
//! device-SMT construction the correction retires. They are not read: a
//! signature over them would feed the retired device root back into this
//! verifier, and everything it would attest is already established by
//! inclusion under a root the lineage walk validated — a walk that itself
//! authenticated the trader under the proven authority.
//!
//! ## What a `VerifiedReceipt` is NOT
//!
//! It is not realization. Amendment 2c-D §11's boundary is explicit: this is
//! verification machinery, and the behavioural cutover is a separate change.
//! Holding one does **not** release a fence, publish anything, promote a
//! market fold out of `PartialPendingRealization`, or construct an
//! [`crate::dlv::successor_validity::IndependentRealization`].

use crate::ccb::CcbError;
use crate::dlv::settlement_receipt_leaf::{SettledTrade, SignedTraderSettlementReceipt};
use crate::economic::lineage::ValidatedEconomicRoot;
use crate::economic::state::{EconomicLeafState, EconomicSettlementReceiptState};
use crate::economic::tree::{leaf_node, root_from_path, ECONOMIC_SMT_HEIGHT};

/// Why a published receipt was refused.
///
/// Structured, never a string: each variant names a distinct way a receipt can
/// fail to correspond to the settlement being verified, and a caller should
/// not have to parse prose to tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishedReceiptInvalid {
    /// The economic path is not exactly [`ECONOMIC_SMT_HEIGHT`] siblings.
    BadSiblingCount { expected: usize, got: usize },
    /// `new_sequence != parent_sequence + 1`.
    NonUnitStep { parent: u64, new: u64 },
    /// The receipt names another vault.
    VaultMismatch {
        receipt: [u8; 32],
        expected: [u8; 32],
    },
    /// The receipt names another trade identity.
    ExternalCommitmentMismatch {
        receipt: [u8; 32],
        expected: [u8; 32],
    },
    /// `receipt_id` is not the derivation of `(vault_id, x)` — a receipt
    /// carrying a name that does not derive from its own contents.
    ReceiptIdNotDerived {
        carried: [u8; 32],
        derived: [u8; 32],
    },
    /// The receipt names an identity other than the independently established
    /// one.
    IdentityMismatch,
    /// The receipt's facts are not a canonical economic receipt state at all
    /// (a zero amount, or one asset on both legs), so no leaf could commit them.
    FactsNotCanonical(CcbError),
    /// The leaf rebuilt from the receipt's facts does not fold to the
    /// validated economic root: some fact differs from what the write set
    /// committed, or the path proves some other tree.
    FactsNotCommittedUnderTheValidatedRoot {
        folded: [u8; 32],
        validated: [u8; 32],
    },
}

impl core::fmt::Display for PublishedReceiptInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSiblingCount { expected, got } => write!(
                f,
                "an economic-SMT path is exactly {expected} siblings; {got} were supplied"
            ),
            Self::NonUnitStep { parent, new } => write!(
                f,
                "the receipt claims sequence {parent} -> {new}; a settlement advances a vault by \
                 exactly one, and a receipt that skipped sequences would fold a vault forward \
                 past states nobody witnessed"
            ),
            Self::VaultMismatch { receipt, expected } => write!(
                f,
                "the receipt settles vault {receipt:02x?}, not {expected:02x?}"
            ),
            Self::ExternalCommitmentMismatch { receipt, expected } => write!(
                f,
                "the receipt names trade {receipt:02x?}, not {expected:02x?}"
            ),
            Self::ReceiptIdNotDerived { carried, derived } => write!(
                f,
                "the receipt carries id {carried:02x?} but (vault, x) derives {derived:02x?}; a \
                 derived name that does not derive from its own contents is the self-rooting \
                 shape this check exists to remove"
            ),
            Self::IdentityMismatch => write!(
                f,
                "the receipt names an identity other than the independently established trader; \
                 its own fields are not authority for whose state it witnesses"
            ),
            Self::FactsNotCanonical(e) => write!(
                f,
                "the receipt's facts are not a canonical economic receipt state ({e}), so no \
                 committed leaf could correspond to them"
            ),
            Self::FactsNotCommittedUnderTheValidatedRoot { folded, validated } => write!(
                f,
                "the receipt's facts fold to {folded:02x?}, not to the validated economic root \
                 {validated:02x?}; the settlement they describe is not the one this trader's \
                 validated transition committed"
            ),
        }
    }
}

/// **Req 21.16's fact.** This published receipt's facts are exactly the
/// settlement receipt the trader's validated economic transition committed.
///
/// Private fields and no public constructor: one exists only because
/// [`verify_published_receipt`] returned it, so holding one IS the fact. It is
/// deliberately narrow — see the module banner for what it does not establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    vault_id: [u8; 32],
    receipt_id: [u8; 32],
    trade: SettledTrade,
    economic_root: [u8; 32],
}

impl VerifiedReceipt {
    /// The vault whose settlement this receipt witnesses.
    pub const fn vault_id(&self) -> [u8; 32] {
        self.vault_id
    }

    /// The receipt identity, RE-DERIVED from `(vault_id, x)` rather than read.
    pub const fn receipt_id(&self) -> [u8; 32] {
        self.receipt_id
    }

    /// The settled trade, in the exact terms an owner must reproduce.
    pub const fn trade(&self) -> SettledTrade {
        self.trade
    }

    /// The VALIDATED economic root the facts were proven under — `R_T^+`,
    /// never a value the receipt supplied.
    pub const fn economic_root(&self) -> [u8; 32] {
        self.economic_root
    }
}

/// **Req 21.16.** Verify a published receipt against facts established
/// independently of it.
///
/// | fact | where it must come from |
/// |---|---|
/// | `validated` (`R_T^+`) | the lineage walk for `(proven_genesis, proven_devid)` |
/// | `economic_path` | anywhere — it is checked, never trusted (the trader's published inclusion proof is the natural source) |
/// | `proven_genesis`, `proven_devid` | the authority resolution |
/// | `expected_vault_id`, `expected_x` | the settlement being verified |
///
/// `validated` must be the root validated for `(proven_genesis,
/// proven_devid)` — the same contract §7 places on its own `validated`
/// parameter. A caller that has only the receipt has nothing to call this
/// with, which is the intended shape.
pub fn verify_published_receipt(
    receipt: &SignedTraderSettlementReceipt,
    validated: &ValidatedEconomicRoot,
    economic_path: &[[u8; 32]],
    proven_genesis: [u8; 32],
    proven_devid: [u8; 32],
    expected_vault_id: [u8; 32],
    expected_x: [u8; 32],
) -> Result<VerifiedReceipt, PublishedReceiptInvalid> {
    // ── shape ────────────────────────────────────────────────────────────
    let siblings: &[[u8; 32]; ECONOMIC_SMT_HEIGHT] =
        economic_path
            .try_into()
            .map_err(|_| PublishedReceiptInvalid::BadSiblingCount {
                expected: ECONOMIC_SMT_HEIGHT,
                got: economic_path.len(),
            })?;
    if receipt.trade.new_sequence != receipt.trade.parent_sequence.saturating_add(1) {
        return Err(PublishedReceiptInvalid::NonUnitStep {
            parent: receipt.trade.parent_sequence,
            new: receipt.trade.new_sequence,
        });
    }

    // ── settlement and party identity: the SETTLEMENT'S, never the receipt's ─
    if receipt.vault_id != expected_vault_id {
        return Err(PublishedReceiptInvalid::VaultMismatch {
            receipt: receipt.vault_id,
            expected: expected_vault_id,
        });
    }
    if receipt.trade.x != expected_x {
        return Err(PublishedReceiptInvalid::ExternalCommitmentMismatch {
            receipt: receipt.trade.x,
            expected: expected_x,
        });
    }
    if receipt.trader_genesis != proven_genesis || receipt.trader_devid != proven_devid {
        return Err(PublishedReceiptInvalid::IdentityMismatch);
    }

    // ── rebuild the leaf the write set would have committed ─────────────
    //
    // From the receipt's FACTS, with vault and x taken from the settlement
    // being verified. The constructor re-derives `receipt_id`, so the carried
    // one is checked against it rather than read.
    let state = EconomicSettlementReceiptState::new(
        expected_vault_id,
        expected_x,
        receipt.trade.parent_sequence,
        receipt.trade.new_sequence,
        receipt.trade.input_policy_commit,
        receipt.trade.input_amount,
        receipt.trade.output_policy_commit,
        receipt.trade.output_amount,
    )
    .map_err(PublishedReceiptInvalid::FactsNotCanonical)?;
    if receipt.receipt_id != state.receipt_id {
        return Err(PublishedReceiptInvalid::ReceiptIdNotDerived {
            carried: receipt.receipt_id,
            derived: state.receipt_id,
        });
    }
    let receipt_id = state.receipt_id;
    let leaf = EconomicLeafState::SettlementReceipt(state);

    // ── fold under the VALIDATED root ────────────────────────────────────
    //
    // Every input to the key is independent of the receipt, so it cannot move
    // its own leaf to a position where some path happens to work; and the
    // value is the canonical encoding of the facts, so a single altered field
    // lands the fold on a different root.
    let key = leaf.leaf_key(&proven_genesis, &proven_devid);
    let value = leaf
        .leaf_value()
        .map_err(PublishedReceiptInvalid::FactsNotCanonical)?;
    let folded = root_from_path(&key, &leaf_node(&key, Some(&value)), siblings);
    let economic_root = validated.economic_root();
    if folded != economic_root {
        return Err(
            PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot {
                folded,
                validated: economic_root,
            },
        );
    }

    Ok(VerifiedReceipt {
        vault_id: expected_vault_id,
        receipt_id,
        trade: receipt.trade,
        economic_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::dlv::settlement_receipt_leaf::{
        derive_receipt_id, settlement_receipt_key, settlement_receipt_value,
        sign_trader_settlement_receipt, verify_trader_settlement_receipt,
    };
    use crate::economic::state::EconomicBalanceState;
    use crate::economic::tree::EconomicSmt;
    use crate::economic::write_set::{
        build_write_set, CreditSourceFacts, EconomicPreState, EconomicWriteContext,
    };
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
    use crate::types::operations::{Operation, TransactionMode};

    const G: [u8; 32] = [0x11; 32];
    const DEV: [u8; 32] = [0x22; 32];
    const VAULT: [u8; 32] = [0x03; 32];
    const X: [u8; 32] = [0xA0; 32];
    const C_DSM_PLUS: [u8; 32] = [0xC5; 32];
    const POSITION: u64 = 3;

    fn settle() -> Operation {
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
            settler_devid: DEV,
            settlement_receipt_id: derive_receipt_id(&VAULT, &X),
            signature: vec![0x77; 48],
            mode: TransactionMode::Unilateral,
        }
    }

    /// The trade exactly as the device advance records it for this settle
    /// (`device_state.rs`, the `DlvSettle` arm) — the facts a published
    /// receipt carries.
    fn trade() -> SettledTrade {
        SettledTrade {
            x: X,
            parent_sequence: 7,
            new_sequence: 8,
            input_policy_commit: [0x10; 32],
            input_amount: 1_000,
            output_policy_commit: [0x20; 32],
            output_amount: 900,
        }
    }

    /// The economic post-state the REAL settle write set leaves behind. The
    /// receipt leaf in it is production's, not one this file assembled to be
    /// checkable — and it shares the tree with the debit, credit and
    /// acceptance leaves, so its path is a real one.
    fn settled_tree() -> EconomicSmt {
        let mut tree = EconomicSmt::new();
        let funded = EconomicLeafState::Balance(
            EconomicBalanceState::new([0x10; 32], 5_000).expect("balance"),
        );
        tree.insert(
            funded.leaf_key(&G, &DEV),
            funded.leaf_value().expect("value"),
        );
        let mut balances = BTreeMap::new();
        balances.insert([0x10; 32], 5_000u64);
        build_write_set(
            &settle(),
            &G,
            &DEV,
            &crate::economic::faucet::dsm_economic_operation_id(&G, &DEV, &C_DSM_PLUS),
            &EconomicPreState::balances_only(&balances),
            &mut tree,
            &CreditSourceFacts::DlvReserveConsumption {
                owner_economic_position: 3,
                reserve_consumption_evidence_addr: [0xEE; 32],
            },
            &EconomicWriteContext::DlvSettle {
                bundle_id: [0xB0; 32],
            },
        )
        .expect("the settle write set builds");
        tree
    }

    /// A legacy receipt object for `trade`, internally consistent over its OWN
    /// one-leaf device tree — the construction the legacy verifier accepts.
    fn legacy_receipt(
        g: [u8; 32],
        dev: [u8; 32],
        trade: SettledTrade,
    ) -> SignedTraderSettlementReceipt {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let receipt_id = derive_receipt_id(&VAULT, &trade.x);
        let key = settlement_receipt_key(&g, &dev, &VAULT, &receipt_id);
        let mut device = SparseMerkleTree::new(64);
        device
            .update_leaf(&key, &settlement_receipt_value(&trade))
            .expect("update_leaf");
        let proof = device.get_inclusion_proof(&key, 256).expect("proof");
        sign_trader_settlement_receipt(
            &VAULT,
            &receipt_id,
            trade,
            &g,
            &dev,
            device.root(),
            proof.siblings,
            &pk,
            &sk,
        )
        .expect("signed")
    }

    struct Fixture {
        receipt: SignedTraderSettlementReceipt,
        validated: ValidatedEconomicRoot,
        path: Vec<[u8; 32]>,
    }

    fn honest() -> Fixture {
        let tree = settled_tree();
        let state =
            EconomicSettlementReceiptState::new(VAULT, X, 7, 8, [0x10; 32], 1_000, [0x20; 32], 900)
                .expect("state");
        let key = EconomicLeafState::SettlementReceipt(state).leaf_key(&G, &DEV);
        Fixture {
            receipt: legacy_receipt(G, DEV, trade()),
            validated: ValidatedEconomicRoot::rehydrate_from_admitted_store(POSITION, tree.root()),
            path: tree.siblings(&key).to_vec(),
        }
    }

    fn verify(f: &Fixture) -> Result<VerifiedReceipt, PublishedReceiptInvalid> {
        verify_published_receipt(&f.receipt, &f.validated, &f.path, G, DEV, VAULT, X)
    }

    #[test]
    fn an_honest_receipt_verifies_under_the_validated_economic_root() {
        let f = honest();
        let v = verify(&f).expect("Req 21.16 holds");
        assert_eq!(v.economic_root(), f.validated.economic_root());
        assert_eq!(v.receipt_id(), derive_receipt_id(&VAULT, &X));
        assert_eq!(v.trade(), trade());
        assert_eq!(v.vault_id(), VAULT);
    }

    /// **THE DEFECT THIS FUNCTION EXISTS TO REMOVE.** A receipt claiming a
    /// trade the trader never committed — here, a better output — is
    /// internally consistent over its own device tree, and the legacy
    /// verifier accepts it. Req 21.16 refuses it, because the validated
    /// economic state does not commit those facts.
    #[test]
    fn a_self_rooted_receipt_is_refused_though_the_legacy_verifier_accepts_it() {
        let mut f = honest();
        let mut inflated = trade();
        inflated.output_amount = 950;
        f.receipt = legacy_receipt(G, DEV, inflated);

        assert!(
            verify_trader_settlement_receipt(&f.receipt).is_ok(),
            "the self-referential check passes, which is exactly the problem"
        );
        assert!(matches!(
            verify(&f),
            Err(PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot { .. })
        ));
    }

    /// **THE D4 CORRECTION AS A CONTROL.** The receipt's OWN device path does
    /// prove its leaf — under the device root the receipt carries. Handed to
    /// this verifier it proves nothing: it folds to that device root, which is
    /// not the validated economic root, and the legacy leaf is not realization
    /// evidence.
    #[test]
    fn the_receipts_own_device_path_is_not_evidence() {
        let mut f = honest();
        f.path = f.receipt.smt_siblings.clone();
        assert!(matches!(
            verify(&f),
            Err(PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot { .. })
        ));
    }

    /// The legacy fields carry no weight in EITHER direction: a receipt whose
    /// device root, path and signature are garbage still verifies when its
    /// facts are the committed ones. Pinned so the removed signature check is
    /// a visible decision rather than an accident — reinstating it would feed
    /// the retired device root back into this verifier.
    #[test]
    fn the_legacy_device_fields_carry_no_weight_either_way() {
        let mut f = honest();
        f.receipt.post_root = [0x77; 32];
        f.receipt.smt_siblings = vec![[0x55; 32]; 3];
        f.receipt.trader_signature = vec![0u8; 8];
        f.receipt.trader_public_key = vec![0u8; 8];
        verify(&f).expect("the facts are committed under R_T^+, and only they are read");
    }

    /// One named single-field change to a receipt's trade.
    type Alteration = (&'static str, fn(&mut SettledTrade));

    /// Every realization-relevant fact is covered by the fold. Each mutation
    /// below changes ONE field and lands on a different root.
    #[test]
    fn an_altered_amount_asset_or_sequence_is_refused() {
        let alterations: [Alteration; 4] = [
            ("input amount", |t| t.input_amount += 1),
            ("output amount", |t| t.output_amount -= 1),
            ("input asset", |t| t.input_policy_commit = [0x30; 32]),
            ("sequence", |t| {
                t.parent_sequence += 1;
                t.new_sequence += 1;
            }),
        ];
        for (what, alter) in alterations {
            let mut f = honest();
            alter(&mut f.receipt.trade);
            assert!(
                matches!(
                    verify(&f),
                    Err(PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot { .. })
                ),
                "an altered {what} must not fold to R_T^+"
            );
        }
    }

    /// Key/position: the leaf key is derived from the PROVEN identity, so a
    /// receipt naming another trader is refused before any fold.
    #[test]
    fn a_receipt_naming_another_trader_is_refused() {
        let mut f = honest();
        f.receipt.trader_genesis = [0x99; 32];
        assert_eq!(verify(&f), Err(PublishedReceiptInvalid::IdentityMismatch));
    }

    /// And a proven identity other than the one whose state committed the
    /// receipt keys the leaf elsewhere, so the fold fails even when the receipt
    /// agrees with that identity.
    #[test]
    fn facts_committed_by_another_trader_do_not_verify_for_this_one() {
        let mut f = honest();
        let other = [0x98; 32];
        f.receipt = legacy_receipt(G, other, trade());
        assert!(matches!(
            verify_published_receipt(&f.receipt, &f.validated, &f.path, G, other, VAULT, X),
            Err(PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot { .. })
        ));
    }

    #[test]
    fn a_receipt_for_another_trade_is_refused() {
        let f = honest();
        assert!(matches!(
            verify_published_receipt(&f.receipt, &f.validated, &f.path, G, DEV, VAULT, [0xA1; 32]),
            Err(PublishedReceiptInvalid::ExternalCommitmentMismatch { .. })
        ));
    }

    #[test]
    fn a_receipt_for_another_vault_is_refused() {
        let f = honest();
        assert!(matches!(
            verify_published_receipt(&f.receipt, &f.validated, &f.path, G, DEV, [0x04; 32], X),
            Err(PublishedReceiptInvalid::VaultMismatch { .. })
        ));
    }

    /// A carried id that does not derive from `(vault, x)`.
    #[test]
    fn a_receipt_whose_id_does_not_derive_is_refused() {
        let mut f = honest();
        f.receipt.receipt_id = [0xEE; 32];
        assert!(matches!(
            verify(&f),
            Err(PublishedReceiptInvalid::ReceiptIdNotDerived { .. })
        ));
    }

    /// An altered path cannot fold to the validated root.
    #[test]
    fn an_altered_path_is_refused() {
        let mut f = honest();
        f.path[0] = [0xFF; 32];
        assert!(matches!(
            verify(&f),
            Err(PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot { .. })
        ));
    }

    /// A root validated for some other state proves nothing about this one.
    #[test]
    fn a_path_checked_against_another_validated_root_is_refused() {
        let mut f = honest();
        f.validated = ValidatedEconomicRoot::rehydrate_from_admitted_store(POSITION, [0x77; 32]);
        assert!(matches!(
            verify(&f),
            Err(PublishedReceiptInvalid::FactsNotCommittedUnderTheValidatedRoot { .. })
        ));
    }

    /// A short path is refused rather than padded.
    #[test]
    fn a_short_path_is_refused() {
        let mut f = honest();
        f.path.pop();
        assert_eq!(
            verify(&f),
            Err(PublishedReceiptInvalid::BadSiblingCount {
                expected: 256,
                got: 255
            })
        );
    }

    /// A step that is not +1 is refused by name.
    #[test]
    fn a_non_unit_step_is_refused() {
        let mut f = honest();
        f.receipt.trade.new_sequence = 10;
        assert_eq!(
            verify(&f),
            Err(PublishedReceiptInvalid::NonUnitStep { parent: 7, new: 10 })
        );
    }
}
