// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Connect: a Web2 application connected to a wallet (DSM Amendment A11).
//!
//! The application is a DSM account of its own and never holds a player's
//! keys. The two meet through a `dsm:connect/v1:` code; after pairing the
//! wallet asks the application's own endpoint for requests and posts its
//! answers there. That relay is transport, never evidence: a payment is a
//! transfer accepted onto the application's own relationship, a trade is what
//! SoFi accepts, an issued object is taken only after its policy re-hashes to
//! its anchor, and holdings are a proof the application verifies itself.
//!
//! - [`code`]: the connect code.
//! - [`signed`]: the signed objects, their digests and the identities they
//!   name.
//! - [`grant`]: what a grant lets the application ask for without the player.
//! - [`pinned_tls`]: the HTTPS client bound to the code's certificate pin.
//! - [`holdings`]: the holdings proof, produced by the wallet and verified by
//!   the application.
//! - [`wallet`]: the wallet's side: preview, approve, the listener that
//!   carries out requests, pending approvals, disconnect.
//! - [`app`]: the application's side: offers, sessions, requests, answers and
//!   the facts its own account established.
//! - [`wager`]: the match template a wallet builds for a stake the application
//!   asks it to lock (DSM Amendment A12).

pub mod app;
pub mod code;
pub mod grant;
pub mod holdings;
pub mod pinned_tls;
pub mod signed;
pub mod wager;
pub mod wallet;

/// A 32-byte value from wire bytes, or a refusal naming the field.
pub(crate) fn d32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|e| format!("{what} is {} bytes, not 32: {e}", bytes.len()))
}
