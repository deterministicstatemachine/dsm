// SPDX-License-Identifier: Apache-2.0

//! THE NON-AUTHORITATIVE LOCATOR for a trader's acceptance of one settlement
//! bundle `b` — amendment 2c-D §14, determination D-c.
//!
//! `B` is bound before `TA_B` exists, so `B` cannot name it, and nothing a
//! composer holds — `b`, `X`, the vault, the settler's DevID — lets it derive
//! where `TA_B` lives: `ta_B` hashes bytes that carry the trader's genesis and
//! position, neither of which is in `b`. So the trader publishes this small
//! record under a key derived from `b`, naming two content addresses.
//!
//! **Nothing here is believed.** The locator is transport. `TA_B` is fetched
//! by content address and must pass 2c-D §7 against the exact `b` being
//! composed; the proof artifact is re-verified against the root the trader's
//! own register cell names. A locator that names the wrong bytes makes
//! verification fail — it can never make a wrong acceptance verify. Hence the
//! fetch keeps every failure class distinct and decides nothing else.

use crate::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use crate::util::text_id::encode_base32_crockford;
use dsm::types::proto as generated;
use prost::Message;

/// Storage prefix for trader-acceptance locators, keyed by `b`.
pub(crate) const TRADER_ACCEPTANCE_ROOT: &str = "sofi/trader-acceptance/";

/// The labeled key a locator for bundle `b` is stored under. A label: a node
/// serving other bytes here changes nothing, because nothing read is trusted.
pub(crate) fn locator_key(b: &[u8; 32]) -> String {
    format!("{TRADER_ACCEPTANCE_ROOT}{}", encode_base32_crockford(b))
}

/// Canonical bytes of a locator naming `ta_B` and the admission's proof
/// artifact.
pub(crate) fn encode_locator(ta_b: &[u8; 32], economic_proof_addr: &[u8; 32]) -> Vec<u8> {
    generated::TraderAcceptanceLocatorV1 {
        ta_b: ta_b.to_vec(),
        economic_proof_addr: economic_proof_addr.to_vec(),
    }
    .encode_to_vec()
}

/// What reading the locator for `b` established. Follows `ReceiptFetch`'s
/// shape: an absence is not a failure, an unreadable record establishes
/// nothing, and bytes that are not a locator are a malformation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LocatorFetch {
    /// No record at the key — the trader has not published an acceptance yet.
    Absent,
    /// Could not read. Retryable, and says nothing about whether one exists.
    Unavailable(String),
    /// Bytes are present and are not a canonical locator.
    Malformed(&'static str),
    /// Two content addresses to fetch and verify — nothing more.
    Found {
        ta_b: [u8; 32],
        economic_proof_addr: [u8; 32],
    },
}

/// Decode a locator, requiring canonical bytes and exactly 32-byte fields.
pub(crate) fn decode_locator(bytes: &[u8]) -> LocatorFetch {
    let Ok(l) = generated::TraderAcceptanceLocatorV1::decode(bytes) else {
        return LocatorFetch::Malformed("the bytes do not decode as a trader-acceptance locator");
    };
    if l.encode_to_vec() != bytes {
        return LocatorFetch::Malformed("the locator is not canonical");
    }
    let (Ok(ta_b), Ok(economic_proof_addr)) = (
        <[u8; 32]>::try_from(l.ta_b.as_slice()),
        <[u8; 32]>::try_from(l.economic_proof_addr.as_slice()),
    ) else {
        return LocatorFetch::Malformed("a locator address is not 32 bytes");
    };
    LocatorFetch::Found {
        ta_b,
        economic_proof_addr,
    }
}

/// Read the locator for `b`, keeping every outcome's class.
pub(crate) async fn fetch_locator(b: &[u8; 32]) -> LocatorFetch {
    match BitcoinTapSdk::storage_get_bytes_opt(&locator_key(b)).await {
        Ok(Some(bytes)) => decode_locator(&bytes),
        Ok(None) => LocatorFetch::Absent,
        Err(e) => LocatorFetch::Unavailable(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_locator_round_trips_its_two_addresses() {
        let bytes = encode_locator(&[0xA1; 32], &[0xB2; 32]);
        assert_eq!(
            decode_locator(&bytes),
            LocatorFetch::Found {
                ta_b: [0xA1; 32],
                economic_proof_addr: [0xB2; 32],
            }
        );
    }

    #[test]
    fn a_short_address_is_malformed_not_truncated_or_padded() {
        let bytes = generated::TraderAcceptanceLocatorV1 {
            ta_b: vec![0xA1; 31],
            economic_proof_addr: vec![0xB2; 32],
        }
        .encode_to_vec();
        assert!(matches!(decode_locator(&bytes), LocatorFetch::Malformed(_)));
    }

    #[test]
    fn bytes_that_are_not_a_locator_are_malformed() {
        assert!(matches!(
            decode_locator(&[0xFF, 0xFF, 0xFF]),
            LocatorFetch::Malformed(_)
        ));
    }

    /// The key is a function of `b` alone, so two bundles never share one.
    #[test]
    fn the_key_is_derived_from_the_bundle() {
        assert_ne!(locator_key(&[1; 32]), locator_key(&[2; 32]));
        assert!(locator_key(&[1; 32]).starts_with(TRADER_ACCEPTANCE_ROOT));
    }
}
