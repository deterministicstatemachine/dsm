// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire codec + storage access for `TraderSettlementReceiptV1`.
//!
//! The receipt is what turns a published pending pointer from a claim into a
//! consumable fact. This module is only the transport: it moves receipts to and
//! from storage and converts between the proto and the typed core struct. Every
//! judgement about whether a receipt is *good* lives in
//! [`dsm::dlv::settlement_receipt_leaf::verify_trader_settlement_receipt`], so
//! there is one verifier rather than one per caller.
//!
//! Storage keys are untrusted labels. A receipt fetched from
//! `sofi/vault-receipt/{vault}/{x}` is re-checked against the vault and X the
//! caller actually asked about — a storage node that serves the wrong bytes
//! under the right key changes nothing.

use dsm::dlv::settlement_receipt_leaf::{SettledTrade, SignedTraderSettlementReceipt};
use dsm::types::proto as generated;
use prost::Message;

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::util::text_id::encode_base32_crockford;

/// Storage prefix for settlement receipts, keyed by vault then by the external
/// commitment X of the settlement they witness.
///
/// Keyed by X rather than by receipt id so a composer holding a pointer can
/// fetch its receipt directly, without an index.
pub(crate) const VAULT_RECEIPT_ROOT: &str = "sofi/vault-receipt/";

pub(crate) fn vault_receipt_key(vault_id: &[u8; 32], x: &[u8; 32]) -> String {
    format!(
        "{}{}/{}",
        VAULT_RECEIPT_ROOT,
        encode_base32_crockford(vault_id),
        encode_base32_crockford(x)
    )
}

fn fixed32(v: &[u8]) -> Option<[u8; 32]> {
    if v.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(v);
    Some(out)
}

/// Proto → typed. Returns `None` on any malformed field rather than a partially
/// populated struct, so a truncated or hostile record cannot reach the verifier
/// wearing default values.
pub(crate) fn receipt_from_proto(
    p: &generated::TraderSettlementReceiptV1,
) -> Option<SignedTraderSettlementReceipt> {
    let mut smt_siblings = Vec::with_capacity(p.smt_siblings.len());
    for s in &p.smt_siblings {
        smt_siblings.push(fixed32(s)?);
    }
    Some(SignedTraderSettlementReceipt {
        vault_id: fixed32(&p.vault_id)?,
        receipt_id: fixed32(&p.receipt_id)?,
        trade: SettledTrade {
            x: fixed32(&p.x)?,
            parent_sequence: p.parent_sequence,
            new_sequence: p.new_sequence,
            input_policy_commit: fixed32(&p.input_policy_commit)?,
            input_amount: p.input_amount,
            output_policy_commit: fixed32(&p.output_policy_commit)?,
            output_amount: p.output_amount,
        },
        trader_genesis: fixed32(&p.trader_genesis)?,
        trader_devid: fixed32(&p.trader_devid)?,
        post_root: fixed32(&p.post_root)?,
        smt_siblings,
        trader_public_key: p.trader_public_key.clone(),
        trader_signature: p.trader_signature.clone(),
    })
}

/// Typed → proto.
pub(crate) fn receipt_to_proto(
    r: &SignedTraderSettlementReceipt,
) -> generated::TraderSettlementReceiptV1 {
    generated::TraderSettlementReceiptV1 {
        vault_id: r.vault_id.to_vec(),
        receipt_id: r.receipt_id.to_vec(),
        x: r.trade.x.to_vec(),
        parent_sequence: r.trade.parent_sequence,
        new_sequence: r.trade.new_sequence,
        input_policy_commit: r.trade.input_policy_commit.to_vec(),
        input_amount: r.trade.input_amount,
        output_policy_commit: r.trade.output_policy_commit.to_vec(),
        output_amount: r.trade.output_amount,
        trader_genesis: r.trader_genesis.to_vec(),
        trader_devid: r.trader_devid.to_vec(),
        post_root: r.post_root.to_vec(),
        smt_siblings: r.smt_siblings.iter().map(|s| s.to_vec()).collect(),
        trader_public_key: r.trader_public_key.clone(),
        trader_signature: r.trader_signature.clone(),
    }
}

/// Publish a receipt. Called by the trader AFTER its settling advance commits —
/// the credit is already final at that point, so this write is what makes the
/// consumption visible to everyone else, not what authorizes it.
pub(crate) async fn publish_settlement_receipt(
    receipt: &SignedTraderSettlementReceipt,
) -> Result<(), dsm::types::error::DsmError> {
    let key = vault_receipt_key(&receipt.vault_id, &receipt.trade.x);
    let bytes = receipt_to_proto(receipt).encode_to_vec();
    BitcoinTapSdk::storage_put_bytes(&key, &bytes)
        .await
        .map(|_| ())
}

/// Fetch and fully verify the receipt witnessing the settlement at `(vault, x)`.
///
/// `None` means "no usable receipt", and every route to it is the same to the
/// caller: absent, unfetchable, undecodable, mis-keyed, or failing verification.
/// That collapse is deliberate — the only decision downstream is whether the
/// pointer may be folded, and every one of these says it may not. Reporting them
/// separately would invite a caller to treat some as recoverable and fold
/// anyway.
pub(crate) async fn fetch_verified_receipt(
    vault_id: &[u8; 32],
    x: &[u8; 32],
) -> Option<SignedTraderSettlementReceipt> {
    let key = vault_receipt_key(vault_id, x);
    let bytes = BitcoinTapSdk::storage_get_bytes(&key).await.ok()?;
    let proto = generated::TraderSettlementReceiptV1::decode(bytes.as_slice()).ok()?;
    let receipt = receipt_from_proto(&proto)?;

    // The key is a label the storage node chose to serve these bytes under; the
    // record's own fields are the claim. Require them to agree, or a node could
    // answer a query about one settlement with a receipt for another.
    if receipt.vault_id != *vault_id || receipt.trade.x != *x {
        return None;
    }
    dsm::dlv::settlement_receipt_leaf::verify_trader_settlement_receipt(&receipt).ok()?;
    Some(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::dlv::settlement_receipt_leaf::{
        settlement_receipt_key, settlement_receipt_value, sign_trader_settlement_receipt,
        verify_trader_settlement_receipt,
    };
    use dsm::merkle::sparse_merkle_tree::SparseMerkleTree;

    fn sample() -> SignedTraderSettlementReceipt {
        let (genesis, devid, vault, receipt_id) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        let trade = SettledTrade {
            x: [0x55; 32],
            parent_sequence: 7,
            new_sequence: 8,
            input_policy_commit: [0xE0; 32],
            input_amount: 1_000,
            output_policy_commit: [0xF0; 32],
            output_amount: 970,
        };
        let mut tree = SparseMerkleTree::new(64);
        let key = settlement_receipt_key(&genesis, &devid, &vault, &receipt_id);
        tree.update_leaf(&key, &settlement_receipt_value(&trade))
            .expect("update_leaf");
        let root = *tree.root();
        let sibs = tree.get_inclusion_proof(&key, 256).expect("proof").siblings;
        let (pk, sk) = dsm::crypto::sphincs::generate_sphincs_keypair().expect("keypair");
        sign_trader_settlement_receipt(
            &vault,
            &receipt_id,
            trade,
            &genesis,
            &devid,
            &root,
            sibs,
            &pk,
            &sk,
        )
        .expect("sign")
    }

    /// The wire round-trip must preserve every settled quantity — a receipt that
    /// loses a field on the wire would either fail to verify (best case) or
    /// verify against a different trade than the one that happened.
    #[test]
    fn round_trip_preserves_the_whole_settlement() {
        let r = sample();
        let bytes = receipt_to_proto(&r).encode_to_vec();
        let decoded =
            generated::TraderSettlementReceiptV1::decode(bytes.as_slice()).expect("decode");
        let back = receipt_from_proto(&decoded).expect("typed");

        assert_eq!(back.vault_id, r.vault_id);
        assert_eq!(back.receipt_id, r.receipt_id);
        assert_eq!(back.trade, r.trade);
        assert_eq!(back.trader_genesis, r.trader_genesis);
        assert_eq!(back.trader_devid, r.trader_devid);
        assert_eq!(back.post_root, r.post_root);
        assert_eq!(back.smt_siblings, r.smt_siblings);
        assert_eq!(back.trader_public_key, r.trader_public_key);
        assert_eq!(back.trader_signature, r.trader_signature);

        // And it still verifies after the trip, which the field-by-field
        // comparison above does not by itself establish.
        verify_trader_settlement_receipt(&back).expect("survives the wire");
    }

    /// A malformed record must not decode into a struct wearing zeroed defaults.
    /// A 31-byte root that silently became `[0u8; 32]` would be a receipt
    /// claiming inclusion in the empty tree.
    #[test]
    fn a_malformed_record_decodes_to_nothing_rather_than_to_defaults() {
        let r = sample();
        for (what, mut p) in [
            ("short vault_id", receipt_to_proto(&r)),
            ("short post_root", receipt_to_proto(&r)),
            ("short sibling", receipt_to_proto(&r)),
            ("absent x", receipt_to_proto(&r)),
        ]
        .into_iter()
        .enumerate()
        .map(|(i, (w, mut p))| {
            match i {
                0 => p.vault_id.truncate(31),
                1 => p.post_root.truncate(31),
                2 => p.smt_siblings[0].truncate(31),
                _ => p.x.clear(),
            };
            (w, p)
        }) {
            let _ = &mut p;
            assert!(
                receipt_from_proto(&p).is_none(),
                "{what} must decode to None, not to a default-filled struct"
            );
        }
    }

    /// Sibling count is not checked by the codec — it is the verifier's call —
    /// but a truncated path must still be rejected end to end.
    #[test]
    fn a_truncated_path_survives_decoding_and_dies_at_verification() {
        let r = sample();
        let mut p = receipt_to_proto(&r);
        p.smt_siblings.truncate(255);
        let typed = receipt_from_proto(&p).expect("well-formed fields, wrong count");
        assert!(
            verify_trader_settlement_receipt(&typed).is_err(),
            "a 255-sibling path must not verify"
        );
    }

    #[test]
    fn the_storage_key_is_scoped_to_vault_and_settlement() {
        let (v1, v2) = ([3u8; 32], [9u8; 32]);
        let (x1, x2) = ([0x55u8; 32], [0x66u8; 32]);
        assert_ne!(vault_receipt_key(&v1, &x1), vault_receipt_key(&v2, &x1));
        assert_ne!(vault_receipt_key(&v1, &x1), vault_receipt_key(&v1, &x2));
        assert!(vault_receipt_key(&v1, &x1).starts_with(VAULT_RECEIPT_ROOT));
    }
}
