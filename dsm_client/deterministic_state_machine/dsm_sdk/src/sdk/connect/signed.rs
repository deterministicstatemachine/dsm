// SPDX-License-Identifier: MIT OR Apache-2.0

//! This device's side of DSM Connect's signed objects (DSM Amendment A11):
//! signing a body under its own AK, and the card and network it names
//! itself by.
//!
//! What a signature signs, how one is checked, the canonical-body rule and
//! the identity a card names are Core's (`dsm::connect`): the application
//! and the wallet compute each identically. A device signs Core's
//! [`dsm::connect::statement`].

use dsm::connect::{statement, Signed};
use dsm::types::proto as generated;

/// Sign `body` as `kind` under this device's AK.
pub fn sign_own(kind: Signed, body: &[u8]) -> Result<Vec<u8>, String> {
    let (_, sk) = crate::sdk::signing_authority::current_keypair()
        .map_err(|e| format!("this device's signing key: {e}"))?;
    dsm::crypto::sphincs::sphincs_sign(&sk, &statement(kind, body))
        .map_err(|e| format!("signing the {kind:?}: {e}"))
}

/// This device's own card and AttA, as an offer or an accept carries them.
pub fn own_card() -> Result<(generated::ContactQrV3, [u8; 32]), String> {
    let card = crate::handlers::identity_routes::contact_card()
        .map_err(|e| format!("this device's contact card: {e}"))?;
    let att_a = crate::sdk::signing_authority::current_att_a()
        .map_err(|e| format!("this device's AttA: {e}"))?;
    Ok((card, att_a))
}

/// The network this device's genesis committed, as a card names it.
pub fn own_network() -> Result<String, String> {
    let network = crate::sdk::economic_admission_flow::committed_network_id()
        .map_err(|e| format!("this device's committed network: {e}"))?;
    String::from_utf8(network).map_err(|e| format!("the committed network id: {e}"))
}
