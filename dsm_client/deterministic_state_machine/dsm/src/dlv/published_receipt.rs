// SPDX-License-Identifier: Apache-2.0

//! REQ 21.16 — verifying a published settlement receipt against an
//! INDEPENDENTLY established trader `post_root` (amendment 2c-D, owner ruling
//! D4, recorded at 2c-C4 §9).
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
//! This verifier takes every one of those four from OUTSIDE the receipt. A
//! receipt cannot prove itself by carrying a root and then supplying a path to
//! that same root; the expected `post_root` comes from the already-validated
//! successor / economic-admission path, and the authority from the resolver.
//!
//! ## Which root, and why it is not `R_T^+`
//!
//! Two authenticated structures are in play and they prove different things:
//!
//! ```text
//! acceptance_leaf -> economic SMT     -> R_T^+       2c-D §7
//! receipt leaf    -> trader DEVICE SMT -> post_root  HERE
//! ```
//!
//! Reusing `R_T^+` would be a category error — the public receipt leaf is not
//! an economic-state leaf. `R_T^+` is the root §7 already uses to prove the
//! exact bundle `b` was accepted into the economic post-state; this root
//! proves the published receipt corresponds to the authenticated device
//! post-state rather than being a plausible standalone object.
//!
//! ## What a `VerifiedReceipt` is NOT
//!
//! It is not realization. Amendment 2c-D §11's boundary is explicit: this is
//! verification machinery, and the behavioural cutover is a separate change.
//! Holding one does **not** release a fence, publish anything, promote a
//! market fold out of `PartialPendingRealization`, or construct an
//! [`crate::dlv::successor_validity::IndependentRealization`]. It is one of the
//! facts that will make realization *checkable*.

use crate::dlv::settlement_receipt_leaf::{
    settlement_receipt_key, settlement_receipt_value, SettledTrade, SignedTraderSettlementReceipt,
};
use crate::merkle::sparse_merkle_tree::{SmtInclusionProof, SparseMerkleTree};

/// Why a published receipt was refused.
///
/// Structured, never a string: each variant names a distinct way a receipt can
/// fail to correspond to the settlement being verified, and a caller should
/// not have to parse prose to tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishedReceiptInvalid {
    /// The sibling vector is not exactly 256.
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
    /// The receipt names a post-root other than the independently established
    /// one. Refused BEFORE the fold, so the fold is never run against a root
    /// the receipt chose.
    PostRootMismatch {
        receipt: [u8; 32],
        established: [u8; 32],
    },
    /// The signature does not verify under the independently proven authority.
    SignatureInvalid,
    /// The leaf is not included under the established root.
    InclusionRejected,
}

impl core::fmt::Display for PublishedReceiptInvalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadSiblingCount { expected, got } => write!(
                f,
                "a device-SMT path is exactly {expected} siblings; this receipt carries {got}"
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
                 its own fields are not authority for whose chain it witnesses"
            ),
            Self::PostRootMismatch {
                receipt,
                established,
            } => write!(
                f,
                "the receipt names post-root {receipt:02x?} while the validated advance \
                 established {established:02x?}; a receipt does not get to choose the root it is \
                 proven under"
            ),
            Self::SignatureInvalid => write!(
                f,
                "the receipt does not verify under the independently proven trader authority"
            ),
            Self::InclusionRejected => write!(
                f,
                "the recomputed receipt leaf is not included under the established post-root"
            ),
        }
    }
}

/// **Req 21.16's fact.** This published receipt corresponds to the
/// authenticated device post-state.
///
/// Private fields and no public constructor: one exists only because
/// [`verify_published_receipt`] returned it, so holding one IS the fact. It is
/// deliberately narrow — see the module banner for what it does not establish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedReceipt {
    vault_id: [u8; 32],
    receipt_id: [u8; 32],
    trade: SettledTrade,
    established_post_root: [u8; 32],
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

    /// The INDEPENDENTLY established root the leaf was proven under — never a
    /// value the receipt supplied.
    pub const fn established_post_root(&self) -> [u8; 32] {
        self.established_post_root
    }
}

/// **Req 21.16.** Verify a published receipt against facts established
/// independently of it.
///
/// Every operand that the legacy verifier reads out of the receipt is a
/// parameter here:
///
/// | fact | where it must come from |
/// |---|---|
/// | `established_post_root` | the validated successor / economic-admission path |
/// | `proven_genesis`, `proven_devid` | the authority resolution |
/// | `proven_trader_ak` | the authority resolution |
/// | `expected_vault_id`, `expected_x` | the settlement being verified |
///
/// Passing values taken from the receipt would reproduce exactly the defect
/// this function exists to remove, so a caller that has only the receipt has
/// nothing to call this with — which is the intended shape.
pub fn verify_published_receipt(
    receipt: &SignedTraderSettlementReceipt,
    established_post_root: [u8; 32],
    proven_genesis: [u8; 32],
    proven_devid: [u8; 32],
    proven_trader_ak: &[u8],
    expected_vault_id: [u8; 32],
    expected_x: [u8; 32],
) -> Result<VerifiedReceipt, PublishedReceiptInvalid> {
    // ── 1. shape ─────────────────────────────────────────────────────────
    if receipt.smt_siblings.len() != 256 {
        return Err(PublishedReceiptInvalid::BadSiblingCount {
            expected: 256,
            got: receipt.smt_siblings.len(),
        });
    }
    if receipt.trade.new_sequence != receipt.trade.parent_sequence.saturating_add(1) {
        return Err(PublishedReceiptInvalid::NonUnitStep {
            parent: receipt.trade.parent_sequence,
            new: receipt.trade.new_sequence,
        });
    }

    // ── 2/3. settlement identity correspondence ──────────────────────────
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
    // RE-DERIVED from the settlement being verified, never read.
    let receipt_id =
        crate::dlv::settlement_receipt_leaf::derive_receipt_id(&expected_vault_id, &expected_x);
    if receipt.receipt_id != receipt_id {
        return Err(PublishedReceiptInvalid::ReceiptIdNotDerived {
            carried: receipt.receipt_id,
            derived: receipt_id,
        });
    }

    // ── the identity and the root are ESTABLISHED, not read ──────────────
    if receipt.trader_genesis != proven_genesis || receipt.trader_devid != proven_devid {
        return Err(PublishedReceiptInvalid::IdentityMismatch);
    }
    // Checked BEFORE the fold. The signature below covers `post_root`, so
    // requiring the receipt to NAME the established root is what binds the
    // trader's signature to it — and the fold then runs against the
    // established value regardless.
    if receipt.post_root != established_post_root {
        return Err(PublishedReceiptInvalid::PostRootMismatch {
            receipt: receipt.post_root,
            established: established_post_root,
        });
    }

    // ── signature, under the PROVEN authority ────────────────────────────
    let payload = crate::dlv::settlement_receipt_leaf::receipt_sign_payload(
        &expected_vault_id,
        &receipt_id,
        &receipt.trade,
        &proven_genesis,
        &proven_devid,
        &established_post_root,
    );
    let ok = crate::crypto::sphincs::sphincs_verify(
        proven_trader_ak,
        &payload,
        &receipt.trader_signature,
    )
    .map_err(|_| PublishedReceiptInvalid::SignatureInvalid)?;
    if !ok {
        return Err(PublishedReceiptInvalid::SignatureInvalid);
    }

    // ── 4/5. reconstruct the leaf and fold to the ESTABLISHED root ───────
    //
    // Every input to the key comes from outside the receipt, so a receipt
    // cannot move its own leaf to a position where some path happens to work.
    let key = settlement_receipt_key(
        &proven_genesis,
        &proven_devid,
        &expected_vault_id,
        &receipt_id,
    );
    let proof = SmtInclusionProof {
        key,
        value: Some(settlement_receipt_value(&receipt.trade)),
        siblings: receipt.smt_siblings.clone(),
    };
    if !SparseMerkleTree::verify_proof_against_root(&proof, &established_post_root) {
        return Err(PublishedReceiptInvalid::InclusionRejected);
    }

    Ok(VerifiedReceipt {
        vault_id: expected_vault_id,
        receipt_id,
        trade: receipt.trade,
        established_post_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dlv::settlement_receipt_leaf::{derive_receipt_id, sign_trader_settlement_receipt};

    const G: [u8; 32] = [0x11; 32];
    const DEV: [u8; 32] = [0x22; 32];
    const VAULT: [u8; 32] = [0x03; 32];
    const X: [u8; 32] = [0xA0; 32];

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

    /// The receipt leaf inserted into a real device SMT, and the root that
    /// results. The root is computed HERE, from the tree — it is the
    /// "independently established" value the verifier is given, and the
    /// receipt merely names it.
    fn established_root(g: [u8; 32], dev: [u8; 32]) -> ([u8; 32], Vec<[u8; 32]>) {
        let receipt_id = derive_receipt_id(&VAULT, &X);
        let key = settlement_receipt_key(&g, &dev, &VAULT, &receipt_id);
        let value = settlement_receipt_value(&trade());
        let mut tree = SparseMerkleTree::new(64);
        tree.update_leaf(&key, &value).expect("update_leaf");
        let proof = tree.get_inclusion_proof(&key, 256).expect("proof");
        (*tree.root(), proof.siblings)
    }

    struct Fixture {
        receipt: SignedTraderSettlementReceipt,
        root: [u8; 32],
        ak: Vec<u8>,
    }

    fn honest() -> Fixture {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let (root, siblings) = established_root(G, DEV);
        let receipt = sign_trader_settlement_receipt(
            &VAULT,
            &derive_receipt_id(&VAULT, &X),
            trade(),
            &G,
            &DEV,
            &root,
            siblings,
            &pk,
            &sk,
        )
        .expect("signed");
        Fixture {
            receipt,
            root,
            ak: pk,
        }
    }

    fn verify(f: &Fixture) -> Result<VerifiedReceipt, PublishedReceiptInvalid> {
        verify_published_receipt(&f.receipt, f.root, G, DEV, &f.ak, VAULT, X)
    }

    #[test]
    fn an_honest_receipt_verifies_under_the_established_root() {
        let f = honest();
        let v = verify(&f).expect("Req 21.16 holds");
        assert_eq!(v.established_post_root(), f.root);
        assert_eq!(v.receipt_id(), derive_receipt_id(&VAULT, &X));
        assert_eq!(v.trade(), trade());
    }

    /// **THE DEFECT THIS FUNCTION EXISTS TO REMOVE.** A receipt that carries
    /// its own root, signs over it, and supplies a path to it is internally
    /// consistent — the legacy verifier accepts it. Req 21.16 refuses it,
    /// because the root it was asked to prove against is not the one the
    /// validated advance established.
    #[test]
    fn a_self_rooted_receipt_is_refused_though_it_is_internally_consistent() {
        // A receipt built over a DIFFERENT identity's tree: self-consistent,
        // and rooted at a value nobody else established.
        let other_g = [0x99; 32];
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        let (rogue_root, siblings) = established_root(other_g, DEV);
        let receipt = sign_trader_settlement_receipt(
            &VAULT,
            &derive_receipt_id(&VAULT, &X),
            trade(),
            &other_g,
            &DEV,
            &rogue_root,
            siblings,
            &pk,
            &sk,
        )
        .expect("signed");

        // The legacy verifier, which reads everything out of the receipt,
        // accepts it — that is the property being contrasted, not a bug here.
        assert!(
            crate::dlv::settlement_receipt_leaf::verify_trader_settlement_receipt(&receipt).is_ok(),
            "the self-referential check passes, which is exactly the problem"
        );

        // Req 21.16, given the ESTABLISHED root, refuses.
        let established = honest().root;
        assert!(matches!(
            verify_published_receipt(&receipt, established, G, DEV, &pk, VAULT, X),
            Err(PublishedReceiptInvalid::IdentityMismatch)
                | Err(PublishedReceiptInvalid::PostRootMismatch { .. })
        ));
    }

    /// The root is not negotiable: a receipt naming any other root is refused
    /// BEFORE the fold, so the fold never runs against a receipt-chosen value.
    #[test]
    fn a_receipt_naming_another_root_is_refused() {
        let f = honest();
        assert!(matches!(
            verify_published_receipt(&f.receipt, [0x77; 32], G, DEV, &f.ak, VAULT, X),
            Err(PublishedReceiptInvalid::PostRootMismatch { .. })
        ));
    }

    /// The authority is not the receipt's. A receipt signed by someone else is
    /// refused even though its own `trader_public_key` would verify it.
    #[test]
    fn a_receipt_signed_by_another_authority_is_refused() {
        let f = honest();
        let (other_pk, _) = crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        assert_eq!(
            verify_published_receipt(&f.receipt, f.root, G, DEV, &other_pk, VAULT, X),
            Err(PublishedReceiptInvalid::SignatureInvalid)
        );
    }

    /// The settlement identity must correspond: a receipt for another trade is
    /// refused even when everything else is honest.
    #[test]
    fn a_receipt_for_another_trade_is_refused() {
        let f = honest();
        assert!(matches!(
            verify_published_receipt(&f.receipt, f.root, G, DEV, &f.ak, VAULT, [0xA1; 32]),
            Err(PublishedReceiptInvalid::ExternalCommitmentMismatch { .. })
        ));
    }

    /// A receipt for another vault is refused.
    #[test]
    fn a_receipt_for_another_vault_is_refused() {
        let f = honest();
        assert!(matches!(
            verify_published_receipt(&f.receipt, f.root, G, DEV, &f.ak, [0x04; 32], X),
            Err(PublishedReceiptInvalid::VaultMismatch { .. })
        ));
    }

    /// An altered path cannot fold to the established root.
    #[test]
    fn an_altered_path_is_refused() {
        let mut f = honest();
        f.receipt.smt_siblings[0] = [0xFF; 32];
        assert_eq!(verify(&f), Err(PublishedReceiptInvalid::InclusionRejected));
    }

    /// A short path is refused rather than padded.
    #[test]
    fn a_short_path_is_refused() {
        let mut f = honest();
        f.receipt.smt_siblings.pop();
        assert!(matches!(
            verify(&f),
            Err(PublishedReceiptInvalid::BadSiblingCount {
                expected: 256,
                got: 255
            })
        ));
    }
}
