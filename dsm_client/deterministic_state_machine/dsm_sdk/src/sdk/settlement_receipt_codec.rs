// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wire codec + storage access for `TraderSettlementReceiptV1`.
//!
//! TRANSPORT ONLY (2c-D §14, ruling C2-R1 point 8). This module moves receipts
//! to and from storage and converts between the proto and the typed core
//! struct. It never judges whether a receipt is true: that is Req 21.16
//! ([`dsm::dlv::published_receipt::verify_published_receipt`]), which the
//! composition walk runs against the trader's validated `R_T^+`. A decoded
//! receipt is evidence, never settlement.
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

/// TEST FIXTURE: plant a receipt at its key. Not the production path — it
/// returns `Ok` when ONE node accepts, which cannot discharge 2c-D §14 C2-R1
/// point 4. The settling trader publishes its receipt as a frozen publication
/// artifact and releases its fence only once that artifact is published at
/// quorum (D-b).
#[cfg(test)]
pub(crate) async fn publish_settlement_receipt(
    receipt: &SignedTraderSettlementReceipt,
) -> Result<(), dsm::types::error::DsmError> {
    let key = vault_receipt_key(&receipt.vault_id, &receipt.trade.x);
    let bytes = receipt_to_proto(receipt).encode_to_vec();
    BitcoinTapSdk::storage_put_bytes(&key, &bytes)
        .await
        .map(|_| ())
}

/// What READING the receipt at `(vault, x)` established — transport and
/// decoding only (2c-D §14, ruling C2-R1 point 8). Nothing here says whether the
/// receipt is TRUE: that is Req 21.16's, against the validated `R_T^+`, inside
/// the composition walk.
#[derive(Debug)]
pub(crate) enum ReceiptFetch {
    /// No object at the key — not published yet.
    Absent,
    /// Could not read. Retryable, and establishes nothing.
    Unavailable(String),
    /// Bytes are present and are not a receipt for this settlement.
    Malformed(&'static str),
    /// A decoded receipt, with no verification of any kind applied.
    Decoded(Box<SignedTraderSettlementReceipt>),
}

/// Read and decode the receipt at `(vault, x)`. Transport only.
pub(crate) async fn fetch_receipt(vault_id: &[u8; 32], x: &[u8; 32]) -> ReceiptFetch {
    let key = vault_receipt_key(vault_id, x);
    let bytes = match BitcoinTapSdk::storage_get_bytes_opt(&key).await {
        Ok(Some(b)) => b,
        Ok(None) => return ReceiptFetch::Absent,
        Err(e) => return ReceiptFetch::Unavailable(e.to_string()),
    };
    let Ok(proto) = generated::TraderSettlementReceiptV1::decode(bytes.as_slice()) else {
        return ReceiptFetch::Malformed("the bytes at the receipt key do not decode as a receipt");
    };
    let Some(receipt) = receipt_from_proto(&proto) else {
        return ReceiptFetch::Malformed("a receipt field is not 32 bytes");
    };
    if receipt.vault_id != *vault_id || receipt.trade.x != *x {
        return ReceiptFetch::Malformed("the served receipt is for another vault or settlement");
    }
    ReceiptFetch::Decoded(Box::new(receipt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::dlv::settlement_receipt_leaf::{
        settlement_receipt_key, settlement_receipt_value, sign_trader_settlement_receipt,
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
    /// loses a field on the wire would be checked by Req 21.16 against a
    /// different trade than the one that happened.
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

    #[test]
    fn the_storage_key_is_scoped_to_vault_and_settlement() {
        let (v1, v2) = ([3u8; 32], [9u8; 32]);
        let (x1, x2) = ([0x55u8; 32], [0x66u8; 32]);
        assert_ne!(vault_receipt_key(&v1, &x1), vault_receipt_key(&v2, &x1));
        assert_ne!(vault_receipt_key(&v1, &x1), vault_receipt_key(&v1, &x2));
        assert!(vault_receipt_key(&v1, &x1).starts_with(VAULT_RECEIPT_ROOT));
    }
}
